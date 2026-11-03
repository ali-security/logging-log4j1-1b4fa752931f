/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.log4j.net;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InvalidClassException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Vector;

import junit.framework.TestCase;

import org.apache.log4j.Hierarchy;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.apache.log4j.VectorAppender;
import org.apache.log4j.spi.LocationInfo;
import org.apache.log4j.spi.LoggingEvent;
import org.apache.log4j.spi.RootLogger;
import org.apache.log4j.spi.ThrowableInformation;

/**
 * Regression tests for CVE-2019-17571: {@link SocketNode}, which backs
 * {@link SocketServer} and {@link SimpleSocketServer}, must only deserialize
 * the classes making up a {@link LoggingEvent} and refuse any other class
 * (a deserialization gadget) sent by a remote peer.
 */
public class HardenedLoggingEventInputStreamTest extends TestCase {

  static final String LOGGER_NAME = "org.apache.log4j.net.remote";

  /** Number of times a {@link Gadget} instance has been deserialized. */
  static int gadgetReadCount = 0;

  /**
   * Stand-in for a deserialization gadget: its readObject method is the
   * attacker controlled code that runs as soon as the class is deserialized.
   */
  public static class Gadget implements Serializable {
    private static final long serialVersionUID = 1L;
    final String command;

    public Gadget(String command) {
      this.command = command;
    }

    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
      in.defaultReadObject();
      gadgetReadCount++;
    }
  }

  public HardenedLoggingEventInputStreamTest(String name) {
    super(name);
  }

  protected void setUp() {
    gadgetReadCount = 0;
  }

  static byte[] serialize(Object[] objects) throws IOException {
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    ObjectOutputStream oos = new ObjectOutputStream(baos);
    for (int i = 0; i < objects.length; i++) {
      oos.writeObject(objects[i]);
    }
    oos.close();
    return baos.toByteArray();
  }

  static LoggingEvent makeEvent(String message, Map properties, Throwable t) {
    Logger logger = Logger.getLogger(LOGGER_NAME);
    ThrowableInformation ti = null;
    if (t != null) {
      ti = new ThrowableInformation(t, logger);
    }
    LocationInfo li = new LocationInfo("Remote.java", "org.example.Remote", "doIt", "42");
    return new LoggingEvent(Logger.class.getName(), logger, System.currentTimeMillis(),
        Level.WARN, message, "remote-thread", ti, "remote-ndc", li, properties);
  }

  static Object readSingle(byte[] bytes) throws IOException, ClassNotFoundException {
    HardenedLoggingEventInputStream hleis =
        new HardenedLoggingEventInputStream(new ByteArrayInputStream(bytes));
    try {
      return hleis.readObject();
    } finally {
      hleis.close();
    }
  }

  static void assertRejected(InvalidClassException e, String className) {
    String msg = e.getMessage();
    assertNotNull(msg);
    assertTrue(msg, msg.indexOf("Unauthorized deserialization attempt") >= 0);
    assertTrue(msg, msg.indexOf(className) >= 0);
  }

  /**
   * A genuine logging event, with MDC, NDC, location and throwable
   * information, still goes through the hardened stream.
   */
  public void testLoggingEventIsAccepted() throws Exception {
    Map props = new HashMap();
    props.put("hostID", "client-1");
    LoggingEvent sent = makeEvent("hello", props, new Exception("testing"));

    Object o = readSingle(serialize(new Object[] { sent }));

    assertTrue(o instanceof LoggingEvent);
    LoggingEvent received = (LoggingEvent) o;
    assertEquals(LOGGER_NAME, received.getLoggerName());
    assertEquals(Level.WARN, received.getLevel());
    assertEquals("hello", received.getRenderedMessage());
    assertEquals("remote-ndc", received.getNDC());
    assertEquals("remote-thread", received.getThreadName());
    assertEquals("client-1", received.getProperty("hostID"));
    assertEquals("42", received.getLocationInformation().getLineNumber());
    String[] rep = received.getThrowableStrRep();
    assertNotNull(rep);
    assertEquals("java.lang.Exception: testing", rep[0]);
  }

  /**
   * An arbitrary serializable class sent in place of a logging event is
   * rejected before its readObject method can run.
   */
  public void testTopLevelGadgetIsRejected() throws Exception {
    byte[] bytes = serialize(new Object[] { new Gadget("touch /tmp/pwned") });
    try {
      readSingle(bytes);
      fail("Gadget class should not have been deserialized");
    } catch (InvalidClassException e) {
      assertRejected(e, Gadget.class.getName());
    }
    assertEquals(0, gadgetReadCount);
  }

  /**
   * BadPayload throws from its readObject method; it must never get there.
   */
  public void testBadPayloadIsRejected() throws Exception {
    byte[] bytes = serialize(new Object[] { new BadPayload("x") });
    try {
      readSingle(bytes);
      fail("BadPayload should not have been deserialized");
    } catch (InvalidClassException e) {
      assertRejected(e, BadPayload.class.getName());
    }
  }

  /**
   * A gadget smuggled inside an otherwise valid logging event, as the value
   * of an MDC entry, is rejected as well.
   */
  public void testGadgetNestedInLoggingEventIsRejected() throws Exception {
    Map props = new HashMap();
    props.put("hostID", new Gadget("touch /tmp/pwned"));
    LoggingEvent sent = makeEvent("hello", props, null);

    byte[] bytes = serialize(new Object[] { sent });
    try {
      readSingle(bytes);
      fail("Gadget nested in the MDC should not have been deserialized");
    } catch (InvalidClassException e) {
      assertRejected(e, Gadget.class.getName());
    }
    assertEquals(0, gadgetReadCount);
  }

  /**
   * Arrays of classes outside the whitelist are rejected.
   */
  public void testGadgetArrayIsRejected() throws Exception {
    Gadget[] gadgets = new Gadget[] { new Gadget("touch /tmp/pwned") };
    byte[] bytes = serialize(new Object[] { gadgets });
    try {
      readSingle(bytes);
      fail("Gadget array should not have been deserialized");
    } catch (InvalidClassException e) {
      assertRejected(e, Gadget[].class.getName());
    }
    assertEquals(0, gadgetReadCount);
  }

  /**
   * Classes explicitly added to the whitelist are deserialized.
   */
  public void testAdditionalAuthorizedClasses() throws Exception {
    byte[] bytes = serialize(new Object[] { new Gadget("harmless") });
    List extra = new ArrayList();
    extra.add(Gadget.class.getName());
    HardenedLoggingEventInputStream hleis =
        new HardenedLoggingEventInputStream(new ByteArrayInputStream(bytes), extra);
    try {
      Object o = hleis.readObject();
      assertTrue(o instanceof Gadget);
    } finally {
      hleis.close();
    }
    assertEquals(1, gadgetReadCount);
  }

  /**
   * HardenedObjectInputStream rejects any class missing from its whitelist.
   */
  public void testHardenedObjectInputStreamWhitelist() throws Exception {
    byte[] bytes = serialize(new Object[] { new Gadget("touch /tmp/pwned") });
    HardenedObjectInputStream hois = new HardenedObjectInputStream(
        new ByteArrayInputStream(bytes), new String[] { LoggingEvent.class.getName() });
    try {
      hois.readObject();
      fail("Gadget class should not have been deserialized");
    } catch (InvalidClassException e) {
      assertRejected(e, Gadget.class.getName());
    } finally {
      hois.close();
    }
    assertEquals(0, gadgetReadCount);
  }

  /**
   * End to end: a remote peer sends a valid event, then a gadget, then
   * another valid event to a SocketNode. The first event is logged, the
   * gadget is never deserialized and the connection is dropped.
   */
  public void testSocketNodeRejectsGadget() throws Exception {
    Vector logged = runSocketNode(new Object[] {
        makeEvent("first", null, null),
        new Gadget("touch /tmp/pwned"),
        makeEvent("after gadget", null, null) });

    assertEquals(0, gadgetReadCount);
    assertEquals(1, logged.size());
    assertEquals("first", ((LoggingEvent) logged.elementAt(0)).getRenderedMessage());
  }

  /**
   * End to end: a gadget hidden in the MDC of a logging event sent to a
   * SocketNode is never deserialized and the event is not logged.
   */
  public void testSocketNodeRejectsGadgetInsideLoggingEvent() throws Exception {
    Map props = new HashMap();
    props.put("hostID", new Gadget("touch /tmp/pwned"));
    Vector logged = runSocketNode(new Object[] {
        makeEvent("first", null, null),
        makeEvent("carrier", props, null) });

    assertEquals(0, gadgetReadCount);
    assertEquals(1, logged.size());
    assertEquals("first", ((LoggingEvent) logged.elementAt(0)).getRenderedMessage());
  }

  /**
   * CVE-2023-26464: the HashSet DAG from the logback advisory, whose
   * hashCode() costs 2^depth once deserialized.
   */
  static Set nestedHashSets(int depth) {
    Set root = new HashSet();
    Set s1 = root;
    Set s2 = new HashSet();
    for (int i = 0; i < depth; i++) {
      Set t1 = new HashSet();
      Set t2 = new HashSet();
      t1.add("foo");
      s1.add(t1);
      s1.add(t2);
      s2.add(t1);
      s2.add(t2);
      s1 = t1;
      s2 = t2;
    }
    return root;
  }

  /**
   * CVE-2023-26464, end to end: a logging event carrying deeply nested
   * HashSets in its MDC is rejected by the SocketNode instead of keeping it
   * busy computing hash codes, and the connection is dropped.
   */
  public void testSocketNodeRejectsNestedCollectionsInsideLoggingEvent() throws Exception {
    Map props = new HashMap();
    props.put("hostID", nestedHashSets(100));
    Vector logged = runSocketNode(new Object[] {
        makeEvent("first", null, null),
        makeEvent("carrier", props, null),
        makeEvent("after carrier", null, null) });

    assertEquals(1, logged.size());
    assertEquals("first", ((LoggingEvent) logged.elementAt(0)).getRenderedMessage());
  }

  /**
   * The collection budget applies per event: a SocketNode keeps logging a
   * long stream of events that each carry an MDC.
   */
  public void testSocketNodeAcceptsManyEventsWithMdc() throws Exception {
    int count = HardenedObjectInputStream.MAX_COLLECTION_COUNT * 2;
    Object[] events = new Object[count];
    for (int i = 0; i < count; i++) {
      Map props = new HashMap();
      props.put("hostID", "client-" + i);
      events[i] = makeEvent("event " + i, props, null);
    }
    Vector logged = runSocketNode(events);

    assertEquals(count, logged.size());
    LoggingEvent last = (LoggingEvent) logged.elementAt(count - 1);
    assertEquals("event " + (count - 1), last.getRenderedMessage());
    assertEquals("client-" + (count - 1), last.getProperty("hostID"));
  }

  /**
   * Sends the given objects over a TCP connection to a SocketNode, runs the
   * node until the connection ends, and returns the events it logged.
   */
  Vector runSocketNode(final Object[] objects) throws Exception {
    final byte[] bytes = serialize(objects);
    ServerSocket serverSocket = new ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"));
    try {
      final Socket client = new Socket(InetAddress.getByName("127.0.0.1"), serverSocket.getLocalPort());
      Socket accepted = serverSocket.accept();

      Thread writer = new Thread() {
        public void run() {
          try {
            client.getOutputStream().write(bytes);
            client.getOutputStream().flush();
            client.shutdownOutput();
          } catch (IOException e) {
            // the node may close the connection once it rejects the payload
          }
        }
      };
      writer.start();

      Hierarchy hierarchy = new Hierarchy(new RootLogger(Level.DEBUG));
      VectorAppender appender = new VectorAppender();
      hierarchy.getRootLogger().addAppender(appender);

      SocketNode node = new SocketNode(accepted, hierarchy);
      node.run();

      writer.join(5000);
      client.close();
      return appender.getVector();
    } finally {
      serverSocket.close();
    }
  }
}

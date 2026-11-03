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

package org.apache.log4j;

import java.io.StringReader;
import java.util.Properties;

import junit.framework.TestCase;

import org.apache.log4j.xml.DOMConfigurator;

/**
 * The NTEventLogAppender loaded the NTEventLogAppender native library
 * through System.loadLibrary from its static initializer, which searched
 * the PATH and the working directory and so allowed DLL preloading.
 * The appender has been removed; these tests make sure that neither
 * class loading nor configuration can trigger that native library load.
 */
public class NTEventLogAppenderRemovalTest extends TestCase {

  private static final String NT_APPENDER_CLASS =
          "org.apache.log4j.nt.NTEventLogAppender";

  public NTEventLogAppenderRemovalTest(final String name) {
    super(name);
  }

  public void tearDown() {
    LogManager.resetConfiguration();
  }

  /**
   * The appender class must no longer be available.
   */
  public void testClassIsNotAvailable() {
    try {
      Class.forName(NT_APPENDER_CLASS);
      fail(NT_APPENDER_CLASS + " should not be available.");
    } catch (ClassNotFoundException expected) {
    } catch (LinkageError e) {
      fail("Loading " + NT_APPENDER_CLASS
              + " attempted to load a native library: " + e);
    }
  }

  /**
   * A properties configuration naming the appender must not
   * load a native library and must not install the appender.
   */
  public void testPropertyConfiguratorDoesNotLoadNativeLibrary() {
    Properties props = new Properties();
    props.put("log4j.rootLogger", "DEBUG, NT");
    props.put("log4j.appender.NT", NT_APPENDER_CLASS);
    props.put("log4j.appender.NT.layout", "org.apache.log4j.SimpleLayout");
    try {
      PropertyConfigurator.configure(props);
    } catch (LinkageError e) {
      fail("Configuring " + NT_APPENDER_CLASS
              + " attempted to load a native library: " + e);
    }
    assertNull(Logger.getRootLogger().getAppender("NT"));
    Logger.getLogger(NTEventLogAppenderRemovalTest.class).info("Message");
  }

  /**
   * An XML configuration naming the appender must not
   * load a native library and must not install the appender.
   */
  public void testDOMConfiguratorDoesNotLoadNativeLibrary() {
    String xml = "<?xml version=\"1.0\" encoding=\"UTF-8\" ?>\n"
            + "<!DOCTYPE log4j:configuration SYSTEM \"log4j.dtd\">\n"
            + "<log4j:configuration xmlns:log4j=\"http://jakarta.apache.org/log4j/\">\n"
            + "  <appender name=\"NT\" class=\"" + NT_APPENDER_CLASS + "\">\n"
            + "    <layout class=\"org.apache.log4j.SimpleLayout\"/>\n"
            + "  </appender>\n"
            + "  <root>\n"
            + "    <level value=\"debug\"/>\n"
            + "    <appender-ref ref=\"NT\"/>\n"
            + "  </root>\n"
            + "</log4j:configuration>\n";
    try {
      new DOMConfigurator().doConfigure(new StringReader(xml),
              LogManager.getLoggerRepository());
    } catch (LinkageError e) {
      fail("Configuring " + NT_APPENDER_CLASS
              + " attempted to load a native library: " + e);
    }
    assertNull(Logger.getRootLogger().getAppender("NT"));
    Logger.getLogger(NTEventLogAppenderRemovalTest.class).info("Message");
  }
}

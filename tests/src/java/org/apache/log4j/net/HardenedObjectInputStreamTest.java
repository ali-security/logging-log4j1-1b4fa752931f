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
import java.io.InvalidObjectException;
import java.io.ObjectOutputStream;
import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.List;
import java.util.Map;
import java.util.Set;

import junit.framework.TestCase;

/**
 * Tests for {@link HardenedObjectInputStream} collection count limiting
 * that mitigates CVE-2023-26464.
 *
 * CVE-2023-26464: Deeply nested hash-based collection structures cause
 * exponential hashCode() computation during deserialization, leading
 * to Denial of Service. The fix limits the total number of Map/Collection
 * instances that can be deserialized in a single object graph.
 */
public class HardenedObjectInputStreamTest extends TestCase {

    private byte[] serialize(Object obj) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(bos);
        oos.writeObject(obj);
        oos.close();
        return bos.toByteArray();
    }

    /**
     * Reads the payload with {@link HardenedObjectInputStream#readAdaptedObject()}
     * and checks it is refused by the collection limits.
     */
    private void assertCollectionLimitHit(byte[] serialized) throws Exception {
        HardenedObjectInputStream hois = new HardenedObjectInputStream(
                new ByteArrayInputStream(serialized), new String[0]);
        try {
            hois.readAdaptedObject();
            fail("Payload should be rejected by the collection limits");
        } catch (InvalidObjectException e) {
            assertTrue(e.getMessage(), e.getMessage().indexOf("collection") >= 0);
        } finally {
            hois.close();
        }
    }

    /**
     * CVE-2023-26464: The exact attack payload from the logback advisory.
     * Deeply nested HashSet structures that cause exponential hashCode()
     * computation. The collection count limit must reject this before
     * the computation becomes dangerous.
     */
    public void testDeeplyNestedHashSetRejected() throws Exception {
        // Build the CVE-2023-26464 attack payload: deeply nested HashSets
        // that form a DAG causing O(2^N) hashCode() computation
        Set root = new HashSet();
        Set s1 = root;
        Set s2 = new HashSet();
        for (int i = 0; i < 100; i++) {
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
        byte[] serialized = serialize(root);

        ByteArrayInputStream bis = new ByteArrayInputStream(serialized);
        String[] whitelist = new String[0];
        HardenedObjectInputStream hois = new HardenedObjectInputStream(bis, whitelist);

        try {
            hois.readObject();
            fail("Deeply nested HashSet should be rejected due to collection count limit");
        } catch (InvalidObjectException e) {
            // Our resolveObject-based collection count limit caught it (pre-JDK 9)
            assertTrue("Should mention collection limit",
                    e.getMessage().indexOf("collection") >= 0);
        } catch (java.io.InvalidClassException e) {
            // On JDK 9+, the built-in ObjectInputFilter may reject it first
            // with "filter status: REJECTED". Either way, the attack is blocked.
        } finally {
            hois.close();
        }
    }

    /**
     * A moderate number of nested collections (within the limit) should
     * still be allowed. This tests that normal LoggingEvent-like payloads
     * with a few Hashtables work fine.
     */
    public void testModerateCollectionsAllowed() throws Exception {
        // Simulate a LoggingEvent with MDC (Hashtable) containing a few entries
        Hashtable mdc = new Hashtable();
        mdc.put("user", "alice");
        mdc.put("session", "abc123");
        mdc.put("requestId", "req-456");
        byte[] serialized = serialize(mdc);

        ByteArrayInputStream bis = new ByteArrayInputStream(serialized);
        String[] whitelist = new String[0];
        HardenedObjectInputStream hois = new HardenedObjectInputStream(bis, whitelist);

        Object result = hois.readObject();
        assertTrue(result instanceof Hashtable);
        assertEquals("alice", ((Hashtable) result).get("user"));
        hois.close();
    }

    /**
     * Simple non-collection objects should work unaffected.
     */
    public void testStringAllowed() throws Exception {
        byte[] serialized = serialize("hello world");

        ByteArrayInputStream bis = new ByteArrayInputStream(serialized);
        String[] whitelist = new String[0];
        HardenedObjectInputStream hois = new HardenedObjectInputStream(bis, whitelist);

        assertEquals("hello world", hois.readObject());
        hois.close();
    }

    /**
     * A list holding the same nested list twice doubles the hashCode() work
     * with every list read: 30 such lists stay below the collection count
     * limit but cost 2^31 hashCode() calls once the HashSet carrying them
     * hashes its element during deserialization.
     */
    public void testSharedNestedListsRejected() throws Exception {
        List top = new ArrayList();
        Set carrier = new HashSet();
        // hashed while still empty, so building the payload stays cheap
        carrier.add(top);
        List list = new ArrayList();
        for (int i = 0; i < 29; i++) {
            List next = new ArrayList();
            next.add(list);
            next.add(list);
            list = next;
        }
        top.add(list);
        top.add(list);

        assertCollectionLimitHit(serialize(carrier));
    }

    /**
     * Map.Entry objects hash their key and value: a chain of entries each
     * using the previous one as both key and value costs 2^N hashCode()
     * calls, inside a single hash-based collection.
     */
    public void testNestedMapEntriesRejected() throws Exception {
        Map.Entry top = new AbstractMap.SimpleEntry("top", null);
        Set carrier = new HashSet();
        // hashed with a null value, so building the payload stays cheap
        carrier.add(top);
        Map.Entry entry = new AbstractMap.SimpleEntry("key", "value");
        for (int i = 0; i < 100; i++) {
            entry = new AbstractMap.SimpleEntry(entry, entry);
        }
        top.setValue(entry);

        assertCollectionLimitHit(serialize(carrier));
    }

    /**
     * Collections.nCopies lists serialize as a count and a single element:
     * two nested ones cost 2^62 hashCode() calls from a few bytes of input.
     */
    public void testNestedCopiesListsRejected() throws Exception {
        List top = new ArrayList();
        Set carrier = new HashSet();
        // hashed while still empty, so building the payload stays cheap
        carrier.add(top);
        top.add(Collections.nCopies(Integer.MAX_VALUE,
                Collections.nCopies(Integer.MAX_VALUE, "x")));

        assertCollectionLimitHit(serialize(carrier));
    }

    /**
     * Collections shared within the limits, and large flat collections,
     * are still accepted.
     */
    public void testSharedAndFlatCollectionsAllowed() throws Exception {
        Hashtable mdc = new Hashtable();
        for (int i = 0; i < 1000; i++) {
            mdc.put("key" + i, "value" + i);
        }
        List list = new ArrayList();
        list.add(mdc);
        list.add(mdc);
        Set carrier = new HashSet();
        carrier.add(list);
        byte[] serialized = serialize(carrier);

        HardenedObjectInputStream hois = new HardenedObjectInputStream(
                new ByteArrayInputStream(serialized), new String[0]);
        try {
            Set result = (Set) hois.readAdaptedObject();
            assertEquals(1, result.size());
            List resultList = (List) result.iterator().next();
            assertEquals(2, resultList.size());
            assertSame(resultList.get(0), resultList.get(1));
            assertEquals("value999", ((Hashtable) resultList.get(0)).get("key999"));
        } finally {
            hois.close();
        }
    }

    /**
     * Each object read with readAdaptedObject gets its own collection
     * budget, so a long stream of events carrying an MDC is accepted.
     */
    public void testReadAdaptedObjectResetsBudget() throws Exception {
        int count = HardenedObjectInputStream.MAX_COLLECTION_COUNT * 2;
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(bos);
        for (int i = 0; i < count; i++) {
            Hashtable mdc = new Hashtable();
            mdc.put("index", String.valueOf(i));
            oos.writeObject(mdc);
        }
        oos.close();

        HardenedObjectInputStream hois = new HardenedObjectInputStream(
                new ByteArrayInputStream(bos.toByteArray()), new String[0]);
        try {
            for (int i = 0; i < count; i++) {
                Hashtable mdc = (Hashtable) hois.readAdaptedObject();
                assertEquals(String.valueOf(i), mdc.get("index"));
            }
        } finally {
            hois.close();
        }
    }
}

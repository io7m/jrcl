/*
 * Copyright © 2015 <code@io7m.com> http://io7m.com
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR
 * IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package com.io7m.tests.jrcl.core;

import java.io.InputStream;
import java.net.URL;
import java.util.Enumeration;

import org.junit.Assert;
import org.junit.Test;

import com.io7m.jnull.NonNull;
import com.io7m.jnull.NullCheck;
import com.io7m.jrcl.core.JRClassLoader;
import com.io7m.jrcl.core.JRClassLoaderAbstractPolicy;
import com.io7m.jrcl.core.JRClassLoaderPolicyType;
import com.io7m.jrcl.core.JRRuleConclusion;

@SuppressWarnings("static-method") public final class JRClassLoaderTest
{
  private @NonNull ClassLoader getDefaultLoader()
  {
    return NullCheck.notNull(JRClassLoaderTest.class.getClassLoader());
  }

  @Test public void testClassAllowed()
    throws Exception
  {
    final JRClassLoaderPolicyType policy =
      new JRClassLoaderAbstractPolicy(JRRuleConclusion.ALLOW) {
        // Nothing
      };

    final JRClassLoader cl =
      JRClassLoader.getRestrictedClassLoader(this.getDefaultLoader(), policy);

    final Class<?> c = cl.loadClass("java.lang.Object");
    Assert.assertEquals(c, Object.class);
  }

  @Test public void testClassAssertionAllowed()
    throws Exception
  {
    final JRClassLoaderPolicyType policy =
      new JRClassLoaderAbstractPolicy(JRRuleConclusion.ALLOW) {
        // Nothing
      };

    final JRClassLoader cl =
      JRClassLoader.getRestrictedClassLoader(this.getDefaultLoader(), policy);

    cl.setClassAssertionStatus("java.lang.Object", false);
  }

  @Test(expected = SecurityException.class) public
    void
    testClassAssertionDenied()
      throws Exception
  {
    final JRClassLoaderPolicyType policy =
      new JRClassLoaderAbstractPolicy(JRRuleConclusion.DENY) {
        // Nothing
      };

    final JRClassLoader cl =
      JRClassLoader.getRestrictedClassLoader(this.getDefaultLoader(), policy);

    cl.setClassAssertionStatus("java.lang.Object", false);
  }

  @Test(expected = SecurityException.class) public void testClassDenied()
    throws Exception
  {
    final JRClassLoaderPolicyType policy =
      new JRClassLoaderAbstractPolicy(JRRuleConclusion.DENY) {
        // Nothing
      };

    final JRClassLoader cl =
      JRClassLoader.getRestrictedClassLoader(this.getDefaultLoader(), policy);

    cl.loadClass("java.lang.Object");
  }

  @Test public void testResourceAllowed()
    throws Exception
  {
    final JRClassLoaderPolicyType policy =
      new JRClassLoaderAbstractPolicy(JRRuleConclusion.ALLOW) {
        // Nothing
      };

    final JRClassLoader cl =
      JRClassLoader.getRestrictedClassLoader(this.getDefaultLoader(), policy);

    final URL c = cl.getResource("hello.txt");
    System.out.println(c);
  }

  @Test public void testResourceAsStreamAllowed()
    throws Exception
  {
    final JRClassLoaderPolicyType policy =
      new JRClassLoaderAbstractPolicy(JRRuleConclusion.ALLOW) {
        // Nothing
      };

    final JRClassLoader cl =
      JRClassLoader.getRestrictedClassLoader(this.getDefaultLoader(), policy);

    final InputStream c = cl.getResourceAsStream("hello.txt");
    System.out.println(c);
  }

  @Test(expected = SecurityException.class) public
    void
    testResourceAsStreamDenied()
      throws Exception
  {
    final JRClassLoaderPolicyType policy =
      new JRClassLoaderAbstractPolicy(JRRuleConclusion.DENY) {
        // Nothing
      };

    final JRClassLoader cl =
      JRClassLoader.getRestrictedClassLoader(this.getDefaultLoader(), policy);

    cl.getResourceAsStream("hello.txt");
  }

  @Test(expected = SecurityException.class) public void testResourceDenied()
    throws Exception
  {
    final JRClassLoaderPolicyType policy =
      new JRClassLoaderAbstractPolicy(JRRuleConclusion.DENY) {
        // Nothing
      };

    final JRClassLoader cl =
      JRClassLoader.getRestrictedClassLoader(this.getDefaultLoader(), policy);

    cl.getResource("hello.txt");
  }

  @Test public void testResourcesAllowed()
    throws Exception
  {
    final JRClassLoaderPolicyType policy =
      new JRClassLoaderAbstractPolicy(JRRuleConclusion.ALLOW) {
        // Nothing
      };

    final JRClassLoader cl =
      JRClassLoader.getRestrictedClassLoader(this.getDefaultLoader(), policy);

    final Enumeration<URL> c = cl.getResources("hello.txt");
    System.out.println(c);
  }

  @Test(expected = SecurityException.class) public void testResourcesDenied()
    throws Exception
  {
    final JRClassLoaderPolicyType policy =
      new JRClassLoaderAbstractPolicy(JRRuleConclusion.DENY) {
        // Nothing
      };

    final JRClassLoader cl =
      JRClassLoader.getRestrictedClassLoader(this.getDefaultLoader(), policy);

    cl.getResources("hello.txt");
  }
}

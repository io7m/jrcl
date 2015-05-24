package com.io7m.tests.jrcl.core;

import com.io7m.jrcl.core.JRClassLoader;
import com.io7m.jrcl.core.JRClassLoaderPolicyType;

public final class Denial
{
  public static void main(
    final String args[])
    throws Exception
  {
    final ClassLoader cl = ClassLoader.getSystemClassLoader();

    /**
     * A policy that denies everything except <tt>java.lang.Object</tt>.
     */

    final JRClassLoaderPolicyType policy = new JRClassLoaderPolicyType() {
      @Override public boolean policyAllowsResource(
        final String name)
      {
        return false;
      }

      @Override public boolean policyAllowsClass(
        final String name)
      {
        return "java.lang.Object".equals(name);
      }
    };

    final JRClassLoader rcl =
      JRClassLoader.getRestrictedClassLoader(cl, policy);

    /**
     * Permitted
     */

    rcl.loadClass("java.lang.Object");

    /**
     * Not permitted
     */

    try {
      rcl.loadClass("java.lang.Integer");
    } catch (final SecurityException e) {
      System.err.println(e.getMessage());
    }
  }
}

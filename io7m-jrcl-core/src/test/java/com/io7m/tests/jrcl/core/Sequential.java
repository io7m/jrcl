package com.io7m.tests.jrcl.core;

import java.util.regex.Pattern;

import com.io7m.jrcl.core.JRClassLoader;
import com.io7m.jrcl.core.JRRuleConclusion;
import com.io7m.jrcl.core.JRSequentialPolicy;
import com.io7m.jrcl.core.JRSequentialPolicyBuilderType;

public final class Sequential
{
  public static void main(
    final String args[])
    throws Exception
  {
    final ClassLoader cl = ClassLoader.getSystemClassLoader();

    /**
     * A policy that denies everything except <tt>java.lang.Object</tt> and
     * <tt>java.lang.Integer</tt>.
     */

    final JRSequentialPolicyBuilderType jsb =
      JRSequentialPolicy.newPolicyBuilder(
        JRRuleConclusion.DENY,
        JRRuleConclusion.DENY);

    jsb.addClassRule(
      Pattern.compile("java.lang.Object"),
      JRRuleConclusion.ALLOW,
      true);
    jsb.addClassRule(
      Pattern.compile("java.lang.Integer"),
      JRRuleConclusion.ALLOW,
      true);

    final JRClassLoader rcl =
      JRClassLoader.getRestrictedClassLoader(cl, jsb.build());

    /**
     * Permitted
     */

    rcl.loadClass("java.lang.Object");
    rcl.loadClass("java.lang.Integer");

    /**
     * Not permitted
     */

    try {
      rcl.loadClass("java.lang.Float");
    } catch (final SecurityException e) {
      System.err.println(e.getMessage());
    }
  }
}

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

package com.io7m.jrcl.core;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.io7m.jnull.NullCheck;
import com.io7m.junreachable.UnreachableCodeException;

/**
 * <p>
 * A sequential, pattern-based policy.
 * </p>
 *
 * <p>
 * Incoming class and resource names are matched against a series of
 * <i>rules</i>. A rule specifies a <i>pattern</i> and a <i>conclusion</i>.
 * The <i>current conclusion</i> is initially set to the default value as
 * defined by the policy. If a <i>rule's</i> <i>pattern</i> matches the
 * current name, the <i>current conclusion</i> becomes that of the rule. Rules
 * are evaluated from first to last. If a rule is marked as <i>quick</i>,
 * evaluation of rules stops at that point. When evaluation has completed, the
 * <i>current conclusion</i> is returned and used to determine whether or not
 * access is permitted.
 * </p>
 * <p>
 * This scheme was inspired by the OpenBSD PF firewall.
 * </p>
 *
 * @see <a href="http://www.openbsd.org/faq/pf/filter.html">OpenBSD PF</a>
 */

@SuppressWarnings({ "boxing", "synthetic-access" }) public final class JRSequentialPolicy implements
  JRClassLoaderPolicyType
{
  private static final class Builder implements JRSequentialPolicyBuilderType
  {
    private final JRRuleConclusion class_default;
    private final List<Rule>       class_rules;
    private final JRRuleConclusion resource_default;
    private final List<Rule>       resource_rules;

    public Builder(
      final JRRuleConclusion in_class_default,
      final JRRuleConclusion in_resource_default)
    {
      this.class_default = NullCheck.notNull(in_class_default);
      this.resource_default = NullCheck.notNull(in_resource_default);
      this.class_rules = new ArrayList<JRSequentialPolicy.Rule>();
      this.resource_rules = new ArrayList<JRSequentialPolicy.Rule>();
    }

    @Override public void addClassRule(
      final Pattern p,
      final JRRuleConclusion c,
      final boolean quick)
    {
      NullCheck.notNull(p);
      NullCheck.notNull(c);
      this.class_rules.add(new Rule(p, quick, c));
    }

    @Override public void addResourceRule(
      final Pattern p,
      final JRRuleConclusion c,
      final boolean quick)
    {
      NullCheck.notNull(p);
      NullCheck.notNull(c);
      this.resource_rules.add(new Rule(p, quick, c));
    }

    @Override public JRSequentialPolicy build()
    {
      return new JRSequentialPolicy(
        this.class_rules,
        this.resource_rules,
        this.class_default,
        this.resource_default);
    }
  }

  private static final class Rule
  {
    final JRRuleConclusion conclusion;
    final Pattern          pattern;
    final boolean          quick;

    Rule(
      final Pattern in_pattern,
      final boolean in_quick,
      final JRRuleConclusion in_conclusion)
    {
      this.pattern = NullCheck.notNull(in_pattern);
      this.quick = in_quick;
      this.conclusion = NullCheck.notNull(in_conclusion);
    }

    boolean matches(
      final String name)
    {
      final Matcher m = this.pattern.matcher(name);
      return m.matches();
    }
  }

  private static final Logger LOG;

  static {
    LOG =
      NullCheck.notNull(LoggerFactory.getLogger(JRSequentialPolicy.class));
  }

  private static JRRuleConclusion checkRules(
    final String type,
    final String name,
    final JRRuleConclusion default_conclusion,
    final List<Rule> rules)
  {
    JRSequentialPolicy.LOG.debug("{} check {}", type, name);

    JRRuleConclusion current_conclusion = default_conclusion;
    boolean done = false;
    for (int index = 0; index < rules.size(); ++index) {
      final Rule rule = rules.get(index);

      final boolean match = rule.matches(name);
      if (match) {
        current_conclusion = rule.conclusion;
        if (rule.quick) {
          done = true;
        }
      }

      JRSequentialPolicy.LOG.debug(
        "rule [{}]: quick:{} pattern:{} match:{} conclusion:{}",
        index,
        rule.quick,
        rule.pattern,
        match,
        rule.conclusion);

      if (done) {
        break;
      }
    }

    JRSequentialPolicy.LOG.info("class {} {}", current_conclusion, name);
    return current_conclusion;
  }

  /**
   * @param class_default
   *          The default conclusion for classes
   * @param resource_default
   *          The default conclusion for resources
   * @return A new policy builder
   */

  public static JRSequentialPolicyBuilderType newPolicyBuilder(
    final JRRuleConclusion class_default,
    final JRRuleConclusion resource_default)
  {
    return new Builder(class_default, resource_default);
  }

  private final JRRuleConclusion class_default;
  private final List<Rule>       class_rules;
  private final JRRuleConclusion resource_default;
  private final List<Rule>       resource_rules;

  private JRSequentialPolicy(
    final List<Rule> in_class_rules,
    final List<Rule> in_resource_rules,
    final JRRuleConclusion in_class_default,
    final JRRuleConclusion in_resource_default)
  {
    this.class_rules = NullCheck.notNull(in_class_rules);
    this.resource_rules = NullCheck.notNull(in_resource_rules);
    this.class_default = NullCheck.notNull(in_class_default);
    this.resource_default = NullCheck.notNull(in_resource_default);
  }

  @Override public boolean policyAllowsClass(
    final String name)
  {
    NullCheck.notNull(name);

    final JRRuleConclusion current_conclusion =
      JRSequentialPolicy.checkRules(
        "class",
        name,
        this.class_default,
        this.class_rules);

    switch (current_conclusion) {
      case ALLOW:
        return true;
      case DENY:
        return false;
    }

    throw new UnreachableCodeException();
  }

  @Override public boolean policyAllowsResource(
    final String name)
  {
    NullCheck.notNull(name);

    final JRRuleConclusion current_conclusion =
      JRSequentialPolicy.checkRules(
        "resource",
        name,
        this.resource_default,
        this.resource_rules);

    switch (current_conclusion) {
      case ALLOW:
        return true;
      case DENY:
        return false;
    }

    throw new UnreachableCodeException();
  }
}

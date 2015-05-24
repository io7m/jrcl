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

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.util.Enumeration;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.io7m.jnull.NullCheck;
import com.io7m.jnull.Nullable;

/**
 * <p>
 * A restricted classloader.
 * </p>
 * <p>
 * The classloader takes a <i>policy</i> and a <i>delegate</i> classloader as
 * parameters. If the policy allows access to a particular class or resource,
 * the request is passed to the <i>delegate</i>. Otherwise, the classloader
 * raises {@link SecurityException} with an appropriate message.
 * </p>
 */

public final class JRClassLoader extends ClassLoader
{
  private static final Logger LOG;

  static {
    LOG = NullCheck.notNull(LoggerFactory.getLogger(JRClassLoader.class));
  }

  /**
   * Create a new restricted classloader that will forward all allowed
   * requests to the given <tt>in_delegate</tt> based on the policy given by
   * <tt>in_policy</tt>.
   *
   * @param in_delegate
   *          The delegate classloader
   * @param in_policy
   *          The policy
   * @return A new classloader
   */

  public static JRClassLoader getRestrictedClassLoader(
    final ClassLoader in_delegate,
    final JRClassLoaderPolicyType in_policy)
  {
    return new JRClassLoader(in_delegate, in_policy);
  }

  private final ClassLoader             delegate;
  private final JRClassLoaderPolicyType policy;

  private JRClassLoader(
    final ClassLoader in_delegate,
    final JRClassLoaderPolicyType in_policy)
  {
    super(null);
    this.delegate = NullCheck.notNull(in_delegate);
    this.policy = NullCheck.notNull(in_policy);
  }

  @Override public @Nullable URL getResource(
    final @Nullable String in_name)
  {
    final String name = NullCheck.notNull(in_name);

    JRClassLoader.LOG.debug("getResource: {}", name);

    if (this.policy.policyAllowsResource(name)) {
      JRClassLoader.LOG.info("resource ALLOW {}", name);
      return this.delegate.getResource(name);
    }

    JRClassLoader.LOG.info("resource DENY {}", name);
    throw new SecurityException("Access denied: " + name);
  }

  @Override public @Nullable InputStream getResourceAsStream(
    final @Nullable String in_name)
  {
    final String name = NullCheck.notNull(in_name);

    JRClassLoader.LOG.debug("getResourceAsStream: {}", name);

    if (this.policy.policyAllowsResource(name)) {
      JRClassLoader.LOG.info("resource ALLOW {}", name);
      return this.delegate.getResourceAsStream(name);
    }

    JRClassLoader.LOG.info("resource DENY {}", name);
    throw new SecurityException("Access denied: " + name);
  }

  @Override public @Nullable Enumeration<URL> getResources(
    final @Nullable String in_name)
    throws IOException
  {
    final String name = NullCheck.notNull(in_name);

    JRClassLoader.LOG.debug("getResources: {}", name);

    if (this.policy.policyAllowsResource(name)) {
      JRClassLoader.LOG.info("resource ALLOW {}", name);
      return this.delegate.getResources(name);
    }

    JRClassLoader.LOG.info("resource DENY {}", name);
    throw new SecurityException("Access denied: " + name);
  }

  @Override public Class<?> loadClass(
    final @Nullable String in_name)
    throws ClassNotFoundException
  {
    final String name = NullCheck.notNull(in_name);

    JRClassLoader.LOG.debug("loadClass: {}", name);

    if (this.policy.policyAllowsClass(name)) {
      JRClassLoader.LOG.info("class ALLOW {}", name);
      return NullCheck.notNull(this.delegate.loadClass(name));
    }

    JRClassLoader.LOG.info("class DENY {}", name);
    throw new SecurityException("Access denied: " + name);
  }

  @Override public void setClassAssertionStatus(
    final @Nullable String in_name,
    final boolean enabled)
  {
    final String name = NullCheck.notNull(in_name);

    JRClassLoader.LOG.debug("setClassAssertionStatus: {}", name);

    if (this.policy.policyAllowsClass(name)) {
      JRClassLoader.LOG.info("class ALLOW {}", name);
      this.delegate.setClassAssertionStatus(name, enabled);
      return;
    }

    JRClassLoader.LOG.info("class DENY {}", name);
    throw new SecurityException("Access denied: " + name);
  }
}

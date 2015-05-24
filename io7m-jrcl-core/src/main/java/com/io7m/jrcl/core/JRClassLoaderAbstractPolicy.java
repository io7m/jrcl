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

import com.io7m.junreachable.UnreachableCodeException;

/**
 * An abstract policy that can allow or deny all requests by default.
 */

public abstract class JRClassLoaderAbstractPolicy implements
  JRClassLoaderPolicyType
{
  private final JRRuleConclusion default_conclusion;

  protected JRClassLoaderAbstractPolicy(
    final JRRuleConclusion in_default_conclusion)
  {
    this.default_conclusion = in_default_conclusion;
  }

  protected final JRRuleConclusion getDefaultConclusion()
  {
    return this.default_conclusion;
  }

  @Override public boolean policyAllowsClass(
    final String name)
  {
    switch (this.default_conclusion) {
      case ALLOW:
      {
        return true;
      }
      case DENY:
      {
        return false;
      }
    }

    throw new UnreachableCodeException();
  }

  @Override public boolean policyAllowsResource(
    final String name)
  {
    switch (this.default_conclusion) {
      case ALLOW:
      {
        return true;
      }
      case DENY:
      {
        return false;
      }
    }

    throw new UnreachableCodeException();
  }
}

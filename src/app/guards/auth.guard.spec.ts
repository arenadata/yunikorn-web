/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import { TestBed } from '@angular/core/testing';
import { Router } from '@angular/router';
import { RouterTestingModule } from '@angular/router/testing';

import { AuthIdentity } from '@app/models/auth-identity.model';
import { AuthService } from '@app/services/auth/auth.service';
import { AuthGuard } from './auth.guard';

describe('AuthGuard', () => {
  let identity: AuthIdentity;
  let guard: AuthGuard;
  let router: Router;

  beforeEach(() => {
    identity = { mode: 'ldap', user: null, displayName: null };
    TestBed.configureTestingModule({
      imports: [RouterTestingModule],
      providers: [
        AuthGuard,
        { provide: AuthService, useValue: { get currentIdentity() { return identity; } } },
      ],
    });
    guard = TestBed.inject(AuthGuard);
    router = TestBed.inject(Router);
  });

  it('returns login with the requested route when LDAP has no user', () => {
    const result = guard.canActivate({} as any, { url: '/nodes?partition=default' } as any);

    expect(router.serializeUrl(result as any)).toBe('/login?last=%2Fnodes%3Fpartition%3Ddefault');
  });

  it('allows access in other authentication modes', () => {
    identity = { mode: 'kerberos', user: 'alice@EXAMPLE.COM', displayName: 'alice@EXAMPLE.COM' };

    expect(guard.canActivate({} as any, { url: '/nodes' } as any)).toBe(true);
  });
});

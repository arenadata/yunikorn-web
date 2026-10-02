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
import { HttpErrorResponse, HttpHandler, HttpRequest } from '@angular/common/http';
import { Subject, throwError } from 'rxjs';
import { Router } from '@angular/router';
import { RouterTestingModule } from '@angular/router/testing';

import { AuthIdentity } from '@app/models/auth-identity.model';
import { AuthService } from '@app/services/auth/auth.service';
import { ApiErrorInterceptor } from './api-error.interceptor';

describe('ApiErrorInterceptor', () => {
  let interceptor: ApiErrorInterceptor;
  let router: Router;
  let identity: AuthIdentity;
  let authGeneration: number;
  let authServiceStub: {
    readonly currentIdentity: AuthIdentity;
    readonly generation: number;
    clearUser: ReturnType<typeof vi.fn>;
  };

  beforeEach(() => {
    vi.restoreAllMocks();
    identity = { mode: null, user: null, displayName: null };
    authGeneration = 0;
    authServiceStub = {
      get currentIdentity() {
        return identity;
      },
      get generation() {
        return authGeneration;
      },
      clearUser: vi.fn(() => {
        authGeneration += 1;
        identity = { mode: identity.mode, user: null, displayName: null };
      }),
    };
    TestBed.configureTestingModule({
      imports: [RouterTestingModule],
      providers: [ApiErrorInterceptor, { provide: AuthService, useValue: authServiceStub }],
    });
    interceptor = TestBed.inject(ApiErrorInterceptor);
    router = TestBed.inject(Router);
  });

  it('should create the interceptor', () => {
    expect(interceptor).toBeTruthy();
  });

  it('passes auth endpoint errors through without navigating', () => {
    const navigateSpy = vi.spyOn(router, 'navigate');
    const request = new HttpRequest('GET', '/auth/whoami');
    const handler = {
      handle: () => throwError(() => new HttpErrorResponse({ status: 401 })),
    } as HttpHandler;
    let receivedError: HttpErrorResponse | undefined;

    interceptor.intercept(request, handler).subscribe({
      error: (error: HttpErrorResponse) => (receivedError = error),
    });

    expect(receivedError?.status).toBe(401);
    expect(navigateSpy).not.toHaveBeenCalled();
  });

  it('sends an LDAP 401 to login once and preserves the first route', () => {
    identity = { mode: 'ldap', user: 'alice', displayName: 'Alice' };
    authGeneration = 1;
    let resolveNavigation: (result: boolean) => void = () => {};
    const navigateSpy = vi.spyOn(router, 'navigate').mockReturnValue(
      new Promise((resolve) => (resolveNavigation = resolve))
    );
    const request = new HttpRequest('GET', '/ws/v1/nodes');
    const firstResponse = new Subject<any>();
    const secondResponse = new Subject<any>();

    interceptor.intercept(request, { handle: () => firstResponse } as HttpHandler).subscribe({ error: () => {} });
    interceptor.intercept(request, { handle: () => secondResponse } as HttpHandler).subscribe({ error: () => {} });
    firstResponse.error(new HttpErrorResponse({ status: 401 }));
    secondResponse.error(new HttpErrorResponse({ status: 401 }));

    expect(authServiceStub.clearUser).toHaveBeenCalledTimes(1);
    expect(navigateSpy).toHaveBeenCalledTimes(1);
    expect(navigateSpy).toHaveBeenCalledWith(['/login'], { queryParams: { last: '/' } });
    resolveNavigation(true);
  });

  it('ignores an old LDAP 401 after a newer identity is confirmed', () => {
    const pendingResponse = new Subject<any>();
    const handler = { handle: () => pendingResponse } as HttpHandler;
    interceptor.intercept(new HttpRequest('GET', '/ws/v1/nodes'), handler).subscribe({ error: () => {} });

    identity = { mode: 'ldap', user: 'new-user', displayName: 'New User' };
    authGeneration = 2;
    const navigateSpy = vi.spyOn(router, 'navigate');
    pendingResponse.error(new HttpErrorResponse({ status: 401 }));

    expect(identity.user).toBe('new-user');
    expect(authServiceStub.clearUser).not.toHaveBeenCalled();
    expect(navigateSpy).not.toHaveBeenCalled();
  });

  it('redirects when a request from the current LDAP generation returns 401', () => {
    identity = { mode: 'ldap', user: 'new-user', displayName: 'New User' };
    authGeneration = 2;
    const navigateSpy = vi.spyOn(router, 'navigate').mockResolvedValue(true);
    const request = new HttpRequest('GET', '/ws/v1/nodes');
    const handler = {
      handle: () => throwError(() => new HttpErrorResponse({ status: 401 })),
    } as HttpHandler;

    interceptor.intercept(request, handler).subscribe({ error: () => {} });

    expect(authServiceStub.clearUser).toHaveBeenCalledTimes(1);
    expect(navigateSpy).toHaveBeenCalledWith(['/login'], { queryParams: { last: '/' } });
  });

  it('shows the Kerberos ticket message on a Kerberos 401', () => {
    identity = { mode: 'kerberos', user: 'alice@EXAMPLE.COM', displayName: 'alice@EXAMPLE.COM' };
    const navigateSpy = vi.spyOn(router, 'navigate').mockResolvedValue(true);

    interceptor
      .handleApiError(new HttpErrorResponse({ status: 401 }), new HttpRequest('GET', '/ws/v1/nodes'))
      .subscribe({ error: () => {} });

    expect(navigateSpy).toHaveBeenCalledWith(
      ['/error'],
      expect.objectContaining({
        state: expect.objectContaining({
          statusCode: 401,
          message: 'Kerberos ticket required or expired',
        }),
      })
    );
  });

  it('shows the permission message on a 403', () => {
    const navigateSpy = vi.spyOn(router, 'navigate').mockResolvedValue(true);

    interceptor
      .handleApiError(new HttpErrorResponse({ status: 403 }), new HttpRequest('GET', '/ws/v1/nodes'))
      .subscribe({ error: () => {} });

    expect(navigateSpy).toHaveBeenCalledWith(
      ['/error'],
      expect.objectContaining({
        state: expect.objectContaining({
          statusCode: 403,
          message: 'you do not have permission to view this data',
        }),
      })
    );
  });
});

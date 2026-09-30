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

import { HttpClientTestingModule, HttpTestingController } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { firstValueFrom } from 'rxjs';

import { AuthService } from './auth.service';

describe('AuthService', () => {
  let service: AuthService;
  let httpMock: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [HttpClientTestingModule],
      providers: [AuthService],
    });
    service = TestBed.inject(AuthService);
    httpMock = TestBed.inject(HttpTestingController);
  });

  afterEach(() => httpMock.verify());

  it('loads and caches the identity from whoami', () => {
    let loadedIdentity;
    service.loadIdentity().subscribe((identity) => (loadedIdentity = identity));

    httpMock.expectOne('/auth/whoami').flush({ mode: 'kerberos', user: 'alice@EXAMPLE.COM', displayName: 'alice@EXAMPLE.COM' });

    expect(loadedIdentity).toEqual(service.currentIdentity);
    expect(service.currentIdentity.mode).toBe('kerberos');
    expect(service.currentIdentity.user).toBe('alice@EXAMPLE.COM');
    expect(service.generation).toBe(1);
  });

  it('leaves identity unknown when whoami fails', () => {
    let loadedIdentity;
    service.loadIdentity().subscribe((identity) => (loadedIdentity = identity));

    httpMock.expectOne('/auth/whoami').flush('', { status: 503, statusText: 'Unavailable' });

    expect(loadedIdentity).toEqual({ mode: null, user: null, displayName: null });
    expect(service.currentIdentity).toEqual(loadedIdentity);
    expect(service.generation).toBe(1);
  });

  it('keeps startup initialization pending until whoami responds', async () => {
    let initialized = false;
    const initialization = firstValueFrom(service.loadIdentity()).then(() => (initialized = true));
    await Promise.resolve();

    expect(initialized).toBe(false);
    httpMock.expectOne('/auth/whoami').flush({
      mode: 'kerberos',
      user: 'alice@EXAMPLE.COM',
      displayName: 'alice@EXAMPLE.COM',
    });
    await initialization;

    expect(initialized).toBe(true);
  });

  it('loads whoami after a successful LDAP login', () => {
    let loadedIdentity;
    service.login('alice', 'secret').subscribe((identity) => (loadedIdentity = identity));

    const loginRequest = httpMock.expectOne('/auth/login');
    expect(loginRequest.request.method).toBe('POST');
    expect(loginRequest.request.body).toEqual({ username: 'alice', password: 'secret' });
    loginRequest.flush(null, { status: 204, statusText: 'No Content' });
    httpMock.expectOne('/auth/whoami').flush({ mode: 'ldap', user: 'alice', displayName: 'Alice Example' });

    expect(loadedIdentity).toEqual({
      success: true,
      identity: { mode: 'ldap', user: 'alice', displayName: 'Alice Example' },
    });
    expect(service.currentIdentity).toEqual({
      mode: 'ldap',
      user: 'alice',
      displayName: 'Alice Example',
    });
    expect(service.generation).toBe(1);
  });

  it('identifies a login endpoint failure and preserves the known mode', () => {
    let result;
    service.loadIdentity().subscribe();
    httpMock.expectOne('/auth/whoami').flush({ mode: 'ldap', user: null, displayName: null });

    service.login('alice', 'wrong').subscribe((value) => (result = value));
    httpMock.expectOne('/auth/login').flush('', { status: 401, statusText: 'Unauthorized' });

    expect(result).toMatchObject({ success: false, stage: 'login', error: { status: 401 } });
    expect(service.currentIdentity).toEqual({ mode: 'ldap', user: null, displayName: null });
  });

  it('identifies a whoami failure after login and resets identity', () => {
    let result;
    service.loadIdentity().subscribe();
    httpMock.expectOne('/auth/whoami').flush({ mode: 'ldap', user: null, displayName: null });

    service.login('alice', 'secret').subscribe((value) => (result = value));
    httpMock.expectOne('/auth/login').flush(null, { status: 204, statusText: 'No Content' });
    httpMock.expectOne('/auth/whoami').flush('', { status: 503, statusText: 'Unavailable' });

    expect(result).toMatchObject({ success: false, stage: 'whoami', error: { status: 503 } });
    expect(service.currentIdentity).toEqual({ mode: null, user: null, displayName: null });
  });

  it('preserves the LDAP mode after a successful logout', () => {
    service.loadIdentity().subscribe();
    httpMock.expectOne('/auth/whoami').flush({ mode: 'ldap', user: 'alice', displayName: 'Alice Example' });

    service.logout().subscribe();
    const logoutRequest = httpMock.expectOne('/auth/logout');
    expect(logoutRequest.request.method).toBe('POST');
    logoutRequest.flush(null, { status: 204, statusText: 'No Content' });

    expect(service.currentIdentity).toEqual({ mode: 'ldap', user: null, displayName: null });
    expect(service.generation).toBe(2);
  });
});

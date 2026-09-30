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

import { HttpClient, HttpErrorResponse } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { BehaviorSubject, Observable, catchError, map, of, switchMap, tap } from 'rxjs';

import { AuthIdentity, AuthMode, EMPTY_AUTH_IDENTITY } from '@app/models/auth-identity.model';

const AUTH_WHOAMI_URL = '/auth/whoami';
const AUTH_LOGIN_URL = '/auth/login';
const AUTH_LOGOUT_URL = '/auth/logout';
const AUTH_MODES: AuthMode[] = ['ldap', 'kerberos', 'kerberos_ldap', 'mtls', 'shared_secret', 'none'];

export type AuthLoginResult =
  | { success: true; identity: AuthIdentity }
  | { success: false; stage: 'login' | 'whoami'; error: HttpErrorResponse };

@Injectable({
  providedIn: 'root',
})
export class AuthService {
  private readonly identitySubject = new BehaviorSubject<AuthIdentity>(EMPTY_AUTH_IDENTITY);
  readonly identity$ = this.identitySubject.asObservable();
  private authGenerationValue = 0;

  constructor(private httpClient: HttpClient) {}

  get currentIdentity(): AuthIdentity {
    return this.identitySubject.value;
  }

  get generation(): number {
    return this.authGenerationValue;
  }

  loadIdentity(): Observable<AuthIdentity> {
    return this.fetchIdentity().pipe(
      tap((identity) => this.setIdentity(identity)),
      catchError(() => {
        this.resetIdentity();
        return of(EMPTY_AUTH_IDENTITY);
      })
    );
  }

  login(username: string, password: string): Observable<AuthLoginResult> {
    return this.httpClient.post<void>(AUTH_LOGIN_URL, { username, password }).pipe(
      switchMap(() =>
        this.fetchIdentity().pipe(
          map((identity): AuthLoginResult => {
            this.setIdentity(identity);
            return { success: true, identity };
          }),
          catchError((error: HttpErrorResponse) => {
            this.resetIdentity();
            return of({ success: false as const, stage: 'whoami' as const, error });
          })
        )
      ),
      catchError((error: HttpErrorResponse) =>
        of({ success: false as const, stage: 'login' as const, error })
      )
    );
  }

  logout(): Observable<void> {
    return this.httpClient.post<void>(AUTH_LOGOUT_URL, null).pipe(tap(() => this.clearUser()));
  }

  clearUser(): void {
    const { mode } = this.currentIdentity;
    this.setIdentity({ mode, user: null, displayName: null });
  }

  resetIdentity(): void {
    this.setIdentity(EMPTY_AUTH_IDENTITY);
  }

  private fetchIdentity(): Observable<AuthIdentity> {
    return this.httpClient
      .get<AuthIdentity>(AUTH_WHOAMI_URL)
      .pipe(map((identity) => this.normalize(identity)));
  }

  private normalize(identity: AuthIdentity): AuthIdentity {
    const mode = identity?.mode && AUTH_MODES.includes(identity.mode) ? identity.mode : null;

    return {
      mode,
      user: identity?.user || null,
      displayName: identity?.displayName || null,
    };
  }

  private setIdentity(identity: AuthIdentity): void {
    this.authGenerationValue += 1;
    this.identitySubject.next(identity);
  }
}

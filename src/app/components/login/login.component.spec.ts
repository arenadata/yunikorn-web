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

import { CommonModule } from '@angular/common';
import { HttpErrorResponse } from '@angular/common/http';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { FormsModule } from '@angular/forms';
import { MatButtonModule } from '@angular/material/button';
import { MatCardModule } from '@angular/material/card';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { ActivatedRoute, Router } from '@angular/router';
import { RouterTestingModule } from '@angular/router/testing';
import { Subject, of } from 'rxjs';

import { AuthIdentity } from '@app/models/auth-identity.model';
import { AuthLoginResult, AuthService } from '@app/services/auth/auth.service';
import { LoginComponent } from './login.component';

describe('LoginComponent', () => {
  let component: LoginComponent;
  let fixture: ComponentFixture<LoginComponent>;
  let identity: AuthIdentity;
  let lastRoute: string;
  let authServiceStub: { currentIdentity: AuthIdentity; login: ReturnType<typeof vi.fn> };
  let router: Router;
  let originalSecureContext: PropertyDescriptor | undefined;

  const setSecureContext = (isSecure: boolean) => {
    Object.defineProperty(window, 'isSecureContext', { configurable: true, value: isSecure });
  };

  const successfulLogin = (value: AuthIdentity): AuthLoginResult => ({
    success: true,
    identity: value,
  });

  const createComponent = async () => {
    await TestBed.configureTestingModule({
      imports: [
        CommonModule,
        FormsModule,
        MatButtonModule,
        MatCardModule,
        MatFormFieldModule,
        MatInputModule,
        RouterTestingModule,
      ],
      declarations: [LoginComponent],
      providers: [
        { provide: AuthService, useValue: authServiceStub },
        {
          provide: ActivatedRoute,
          useValue: { snapshot: { queryParamMap: { get: (name: string) => name === 'last' ? lastRoute : null } } },
        },
      ],
    }).compileComponents();
    router = TestBed.inject(Router);
    vi.spyOn(router, 'navigateByUrl').mockResolvedValue(true);
    vi.spyOn(router, 'navigate').mockResolvedValue(true);
    fixture = TestBed.createComponent(LoginComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
    await fixture.whenStable();
    fixture.detectChanges();
  };

  beforeEach(() => {
    originalSecureContext = Object.getOwnPropertyDescriptor(window, 'isSecureContext');
    setSecureContext(true);
    identity = { mode: 'ldap', user: null, displayName: null };
    lastRoute = '/nodes?partition=default&filter=running';
    authServiceStub = {
      get currentIdentity() {
        return identity;
      },
      login: vi.fn(() => of(successfulLogin({ mode: 'ldap', user: 'alice', displayName: 'Alice' }))),
    };
  });

  afterEach(() => {
    if (originalSecureContext) {
      Object.defineProperty(window, 'isSecureContext', originalSecureContext);
    } else {
      Reflect.deleteProperty(window, 'isSecureContext');
    }
  });

  it('requires both fields and masks the password', async () => {
    await createComponent();

    const username = fixture.nativeElement.querySelector('input[name="username"]') as HTMLInputElement;
    const password = fixture.nativeElement.querySelector('input[name="password"]') as HTMLInputElement;
    const submit = fixture.nativeElement.querySelector('button[type="submit"]') as HTMLButtonElement;

    expect(username.required).toBe(true);
    expect(password.required).toBe(true);
    expect(password.type).toBe('password');
    expect(submit.disabled).toBe(true);
  });

  it('shows an HTTPS notice instead of the form in an insecure context', async () => {
    setSecureContext(false);
    await createComponent();

    expect(fixture.nativeElement.textContent).toContain('HTTPS required');
    expect(fixture.nativeElement.querySelector('form')).toBeNull();
  });

  it('does not submit a second login while the first request is pending', async () => {
    const pendingLogin = new Subject<AuthLoginResult>();
    authServiceStub.login.mockReturnValue(pendingLogin);
    await createComponent();
    component.username = 'alice';
    component.password = 'secret';

    component.submitLogin();
    component.submitLogin();

    expect(authServiceStub.login).toHaveBeenCalledTimes(1);
    expect(component.isSubmitting).toBe(true);
    pendingLogin.complete();
  });

  it('shows the same generic message for a login 401', async () => {
    authServiceStub.login.mockReturnValue(
      of({ success: false, stage: 'login', error: new HttpErrorResponse({ status: 401 }) })
    );
    await createComponent();
    component.username = 'alice';
    component.password = 'wrong';

    component.submitLogin();

    expect(component.errorMessage).toBe('Invalid username or password.');
    expect(component.errorMessage).not.toContain('alice');
    expect(router.navigateByUrl).not.toHaveBeenCalled();
  });

  it('shows a status for other login failures', async () => {
    authServiceStub.login.mockReturnValue(
      of({ success: false, stage: 'login', error: new HttpErrorResponse({ status: 503 }) })
    );
    await createComponent();
    component.username = 'alice';
    component.password = 'secret';

    component.submitLogin();

    expect(component.errorMessage).toBe('Unable to sign in. Error status: 503.');
  });

  it('returns to the safe in-app last route and keeps its query parameters', async () => {
    await createComponent();
    component.username = 'alice';
    component.password = 'secret';

    component.submitLogin();

    expect(router.navigateByUrl).toHaveBeenCalledWith(lastRoute, { replaceUrl: true });
  });

  it.each(['https://other.example/path', '//other.example/path', '/login?last=%2Fnodes']) (
    'sends unsafe last route %s to the dashboard', async (unsafeLast) => {
      lastRoute = unsafeLast;
      await createComponent();
      component.username = 'alice';
      component.password = 'secret';

      component.submitLogin();

      expect(router.navigateByUrl).toHaveBeenCalledWith('/dashboard', { replaceUrl: true });
    }
  );

  it('stays on the form when whoami returns LDAP without a user', async () => {
    authServiceStub.login.mockReturnValue(
      of(successfulLogin({ mode: 'ldap', user: null, displayName: null }))
    );
    await createComponent();
    component.username = 'alice';
    component.password = 'secret';

    component.submitLogin();

    expect(component.errorMessage).toBe('Unable to establish a session. Please try again.');
    expect(router.navigateByUrl).not.toHaveBeenCalled();
  });

  it.each([
    { last: 'nodes', expectedLast: '/dashboard' },
    { last: '//outside.example/path', expectedLast: '/dashboard' },
    { last: '/login?last=%2Fnodes', expectedLast: '/dashboard' },
    { last: '/nodes?partition=default', expectedLast: '/nodes?partition=default' },
  ])(
    'routes safely after login succeeds but the following whoami fails for $last',
    async ({ last, expectedLast }) => {
      lastRoute = last;
      authServiceStub.login.mockReturnValue(
        of({ success: false, stage: 'whoami', error: new HttpErrorResponse({ status: 503 }) })
      );
      await createComponent();
      component.username = 'alice';
      component.password = 'secret';

      component.submitLogin();

      expect(authServiceStub.login).toHaveBeenCalledWith('alice', 'secret');
      expect(router.navigate).toHaveBeenCalledWith(
        ['/error'],
        expect.objectContaining({
          queryParams: { last: expectedLast },
          state: expect.objectContaining({ authLoginCompletion: true, statusCode: 503 }),
        })
      );
    }
  );

  it.each([
    { mode: 'kerberos', user: 'alice@EXAMPLE.COM', displayName: 'alice@EXAMPLE.COM' },
    { mode: null, user: null, displayName: null },
  ] as AuthIdentity[])('redirects from login when mode is $mode', async (modeIdentity) => {
    identity = modeIdentity;
    await createComponent();

    expect(fixture.nativeElement.querySelector('form')).toBeNull();
    expect(router.navigateByUrl).toHaveBeenCalledWith('/dashboard', { replaceUrl: true });
  });
});

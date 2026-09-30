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

import { HttpErrorResponse } from '@angular/common/http';
import { Component, DestroyRef, OnInit } from '@angular/core';
import { ActivatedRoute, Router } from '@angular/router';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';

import { AuthLoginResult, AuthService } from '@app/services/auth/auth.service';

@Component({
  selector: 'app-login',
  templateUrl: './login.component.html',
  styleUrls: ['./login.component.scss'],
  standalone: false,
})
export class LoginComponent implements OnInit {
  username = '';
  password = '';
  isSubmitting = false;
  errorMessage = '';
  showLoginForm = false;
  readonly isSecureContext = window.isSecureContext;
  private last = '';

  constructor(
    private authService: AuthService,
    private activatedRoute: ActivatedRoute,
    private router: Router,
    private destroyRef: DestroyRef
  ) {}

  ngOnInit(): void {
    this.last = this.activatedRoute.snapshot.queryParamMap.get('last') ?? '';
    const identity = this.authService.currentIdentity;

    if (identity.mode !== 'ldap' || identity.user) {
      void this.router.navigateByUrl('/dashboard', { replaceUrl: true });
      return;
    }

    this.showLoginForm = true;
  }

  submitLogin(): void {
    if (this.isSubmitting || !this.username || !this.password || !this.isSecureContext) {
      return;
    }

    this.isSubmitting = true;
    this.errorMessage = '';
    this.authService
      .login(this.username, this.password)
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: (result: AuthLoginResult) => {
          this.isSubmitting = false;

          if (!result.success) {
            if (result.stage === 'login') {
              this.errorMessage =
                result.error.status === 401
                  ? 'Invalid username or password.'
                  : `Unable to sign in. Error status: ${result.error.status}.`;
            } else {
              this.showIdentityError(result.error);
            }
            return;
          }

          const identity = result.identity;
          if (identity.mode !== 'ldap') {
            void this.router.navigateByUrl('/dashboard', { replaceUrl: true });
            return;
          }

          if (!identity.user) {
            this.errorMessage = 'Unable to establish a session. Please try again.';
            return;
          }

          void this.router.navigateByUrl(this.safeLastRoute(this.last), { replaceUrl: true });
        },
        error: (error: HttpErrorResponse) => {
          this.isSubmitting = false;
          this.errorMessage = `Unable to sign in. Error status: ${error.status}.`;
        },
      });
  }

  private showIdentityError(error: HttpErrorResponse): void {
    const status = error.status;
    void this.router.navigate(['/error'], {
      queryParams: { last: this.safeLastRoute(this.last) },
      state: {
        statusCode: status,
        message: 'Unable to complete sign in',
        description: `Error status: ${status}.`,
        forceDisplay: true,
        authLoginCompletion: true,
      },
    });
  }

  private safeLastRoute(last: string): string {
    if (!last.startsWith('/') || last.startsWith('//') || last.includes('\\')) {
      return '/dashboard';
    }

    try {
      const url = new URL(last, window.location.origin);
      if (
        url.origin !== window.location.origin ||
        url.pathname === '/login' ||
        url.pathname.startsWith('/login/')
      ) {
        return '/dashboard';
      }
      return last;
    } catch {
      return '/dashboard';
    }
  }
}

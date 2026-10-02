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

import { Injectable } from '@angular/core';
import { Router } from '@angular/router';
import { Observable, throwError } from 'rxjs';
import { catchError } from 'rxjs/operators';
import {
  HttpEvent,
  HttpInterceptor,
  HttpHandler,
  HttpRequest,
  HttpErrorResponse,
} from '@angular/common/http';
import { ApiErrorInfo } from '@app/models/api-error-info.model';
import { AuthService } from '@app/services/auth/auth.service';

@Injectable()
export class ApiErrorInterceptor implements HttpInterceptor {
  private ldapLoginNavigationPending = false;

  constructor(
    private router: Router,
    private authService: AuthService
  ) {}

  intercept(request: HttpRequest<any>, next: HttpHandler): Observable<HttpEvent<any>> {
    const requestGeneration = this.authService.generation;

    return next.handle(request).pipe(
      catchError((response: HttpErrorResponse) =>
        this.handleApiError(response, request, requestGeneration)
      )
    );
  }

  handleApiError(
    response: HttpErrorResponse,
    request?: HttpRequest<any>,
    requestGeneration = this.authService.generation
  ) {
    if (request && this.isAuthRequest(request.url)) {
      return throwError(() => response);
    }

    const mode = this.authService.currentIdentity.mode;
    if (response.status === 401 && mode === 'ldap') {
      if (requestGeneration !== this.authService.generation) {
        return throwError(() => response);
      }

      this.authService.clearUser();
      if (!this.router.url.startsWith('/login') && !this.ldapLoginNavigationPending) {
        this.ldapLoginNavigationPending = true;
        const navigation = this.router.navigate(['/login'], {
          queryParams: { last: this.router.url },
        });
        navigation.then(
          () => (this.ldapLoginNavigationPending = false),
          () => (this.ldapLoginNavigationPending = false)
        );
      }
      return throwError(() => response);
    }

    if (response.status === 401 && (mode === 'kerberos' || mode === 'kerberos_ldap')) {
      this.navigateToError(response, 'Kerberos ticket required or expired');
      return throwError(() => response);
    }

    if (response.status === 403) {
      this.navigateToError(response, 'you do not have permission to view this data');
      return throwError(() => response);
    }

    this.navigateToError(response);
    return throwError(() => response);
  }

  parseErrorResponse(error: any, message?: string, statusCode?: number): ApiErrorInfo | undefined {
    if (message) {
      return {
        statusCode: statusCode ?? 0,
        message,
        description: '',
      };
    }

    if (error) {
      return {
        statusCode: error.status_code,
        message: error.message,
        description: error.description,
      };
    } else {
      return undefined;
    }
  }

  private navigateToError(response: HttpErrorResponse, message?: string): void {
    if (!this.router.url.startsWith('/error')) {
      this.router.navigate(['/error'], {
        queryParams: { last: this.router.url },
        state: this.parseErrorResponse(response.error, message, response.status),
      });
    }
  }

  private isAuthRequest(url: string): boolean {
    const path = url.replace(/^https?:\/\/[^/]+/i, '');
    return /^\/auth(?:\/|$)/.test(path);
  }
}

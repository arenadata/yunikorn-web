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

import { Component, DestroyRef, OnInit } from '@angular/core';
import { ActivatedRoute, Router } from '@angular/router';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { ApiErrorInfo } from '@app/models/api-error-info.model';
import { AuthService } from '@app/services/auth/auth.service';

@Component({
  selector: 'app-error-view',
  templateUrl: './error-view.component.html',
  styleUrls: ['./error-view.component.scss'],
  standalone: false,
})
export class ErrorViewComponent implements OnInit {
  apiError: ApiErrorInfo | null = null;
  lastActiveUrl = '';
  isRetrying = false;

  constructor(
    private activatedRoute: ActivatedRoute,
    private router: Router,
    private authService: AuthService,
    private destroyRef: DestroyRef
  ) {}

  ngOnInit() {
    this.apiError = window.history.state;
    this.lastActiveUrl = this.activatedRoute.snapshot.queryParams['last'];
  }

  retryLastActiveUrlAgain() {
    if (this.apiError?.authLoginCompletion) {
      if (this.isRetrying) {
        return;
      }

      this.isRetrying = true;
      this.authService
        .loadIdentity()
        .pipe(takeUntilDestroyed(this.destroyRef))
        .subscribe((identity) => {
          this.isRetrying = false;
          if (identity.mode === 'ldap' && !identity.user) {
            const last = this.lastActiveUrl ? `?last=${encodeURIComponent(this.lastActiveUrl)}` : '';
            void this.router.navigateByUrl(`/login${last}`, { replaceUrl: true });
          } else if (identity.mode) {
            void this.router.navigateByUrl(this.lastActiveUrl || '/dashboard', { replaceUrl: true });
          }
        });
      return;
    }

    if (this.lastActiveUrl) {
      void this.router.navigateByUrl(this.lastActiveUrl);
    } else {
      void this.router.navigateByUrl('/');
    }
  }
}

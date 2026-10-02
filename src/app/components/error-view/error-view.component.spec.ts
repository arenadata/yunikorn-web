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

import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideZoneChangeDetection } from '@angular/core';
import { HttpClientTestingModule, HttpTestingController } from '@angular/common/http/testing';
import { MatCardModule } from '@angular/material/card';
import { Router } from '@angular/router';
import { RouterTestingModule } from '@angular/router/testing';

import { ErrorViewComponent } from './error-view.component';

describe('ErrorViewComponent', () => {
  let component: ErrorViewComponent;
  let fixture: ComponentFixture<ErrorViewComponent>;
  let httpMock: HttpTestingController;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [HttpClientTestingModule, MatCardModule, RouterTestingModule],
      declarations: [ErrorViewComponent],
      providers: [provideZoneChangeDetection()],
    }).compileComponents();
    fixture = TestBed.createComponent(ErrorViewComponent);
    component = fixture.componentInstance;
    httpMock = TestBed.inject(HttpTestingController);
    fixture.detectChanges();
  });

  afterEach(() => httpMock.verify());

  it('should create the component', () => {
    expect(component).toBeTruthy();
  });

  it('retries whoami and returns to the saved in-app route when identity is confirmed', async () => {
    const router = TestBed.inject(Router);
    const navigateSpy = vi.spyOn(router, 'navigateByUrl').mockResolvedValue(true);
    component.apiError = {
      statusCode: 503,
      message: 'Unable to complete sign in',
      description: 'Error status: 503.',
      authLoginCompletion: true,
    };
    component.lastActiveUrl = '/nodes?partition=default';

    (fixture.nativeElement.querySelector('.try-btn') as HTMLButtonElement).click();
    fixture.detectChanges();
    httpMock.expectOne('/auth/whoami').flush({ mode: 'ldap', user: 'alice', displayName: 'Alice' });
    await fixture.whenStable();
    fixture.detectChanges();

    expect(navigateSpy).toHaveBeenCalledWith('/nodes?partition=default', { replaceUrl: true });
  });
});

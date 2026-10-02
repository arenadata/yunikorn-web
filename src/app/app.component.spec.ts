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

import { TestBed, ComponentFixture } from '@angular/core/testing';
import { RouterTestingModule } from '@angular/router/testing';
import { NgxSpinnerModule } from 'ngx-spinner';
import { MatMenuModule } from '@angular/material/menu';
import { MatTooltipModule } from '@angular/material/tooltip';
import { MatButtonModule } from '@angular/material/button';
import { provideZoneChangeDetection } from '@angular/core';
import { HAMMER_LOADER } from '@angular/platform-browser';
import { Router } from '@angular/router';
import { MatMenuHarness } from '@angular/material/menu/testing';
import { TestbedHarnessEnvironment } from '@angular/cdk/testing/testbed';
import { BehaviorSubject, Subject, tap } from 'rxjs';

import { AppComponent } from './app.component';
import { EventBusService } from './services/event-bus/event-bus.service';
import { MockEventBusService } from './testing/mocks';
import { MatDialog } from '@angular/material/dialog';
import { CommonModule } from '@angular/common';
import { AuthIdentity } from './models/auth-identity.model';
import { AuthService } from './services/auth/auth.service';

describe('AppComponent', () => {
  let component: AppComponent;
  let fixture: ComponentFixture<AppComponent>;
  let identitySubject: BehaviorSubject<AuthIdentity>;
  let logoutRequests: Subject<void>[];
  let authServiceStub: {
    identity$: BehaviorSubject<AuthIdentity>;
    logout: ReturnType<typeof vi.fn>;
  };

  beforeEach(async () => {
    identitySubject = new BehaviorSubject<AuthIdentity>({ mode: null, user: null, displayName: null });
    logoutRequests = [];
    authServiceStub = {
      identity$: identitySubject,
      logout: vi.fn(() => {
        const request = new Subject<void>();
        logoutRequests.push(request);
        return request.pipe(
          tap(() => identitySubject.next({ ...identitySubject.value, user: null, displayName: null }))
        );
      }),
    };
    await TestBed.configureTestingModule({
      declarations: [AppComponent],
      imports: [
        RouterTestingModule,
        CommonModule,
        NgxSpinnerModule,
        MatMenuModule,
        MatTooltipModule,
        MatButtonModule,
      ],
      providers: [
        provideZoneChangeDetection(),
        { provide: EventBusService, useValue: MockEventBusService },
        { provide: HAMMER_LOADER, useValue: () => new Promise(() => {}) },
        { provide: MatDialog, useValue: { open: vi.fn() } },
        { provide: AuthService, useValue: authServiceStub },
      ],
    }).compileComponents();
    fixture = TestBed.createComponent(AppComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create the component', () => {
    expect(component).toBeTruthy();
  });

  it('updates the header identity without reloading and only exposes the LDAP logout menu', () => {
    identitySubject.next({ mode: 'ldap', user: 'alice', displayName: 'Alice Example' });
    fixture.detectChanges();

    expect(fixture.nativeElement.querySelector('.user-menu-trigger')?.textContent).toContain('Alice Example');

    identitySubject.next({ mode: 'kerberos', user: 'alice@EXAMPLE.COM', displayName: 'alice@EXAMPLE.COM' });
    fixture.detectChanges();

    expect(fixture.nativeElement.querySelector('.user-name')?.textContent).toContain('alice@EXAMPLE.COM');
    expect(fixture.nativeElement.querySelector('.user-menu-trigger')).toBeNull();
  });

  it('clears the LDAP user and navigates to login after logout succeeds', () => {
    identitySubject.next({ mode: 'ldap', user: 'alice', displayName: 'Alice Example' });
    fixture.detectChanges();
    const router = TestBed.inject(Router);
    const navigateSpy = vi.spyOn(router, 'navigateByUrl').mockResolvedValue(true);

    component.logout();
    logoutRequests[0].next();
    logoutRequests[0].complete();

    expect(identitySubject.value).toEqual({ mode: 'ldap', user: null, displayName: null });
    expect(navigateSpy).toHaveBeenCalledWith('/login', { replaceUrl: true });
  });

  it('shows logout errors and permits a retry', async () => {
    identitySubject.next({ mode: 'ldap', user: 'alice', displayName: 'Alice Example' });
    fixture.detectChanges();

    const loader = TestbedHarnessEnvironment.loader(fixture);
    const userMenu = await loader.getHarness(
      MatMenuHarness.with({ selector: '.user-menu-trigger' })
    );
    await userMenu.open();
    const logoutItems = await userMenu.getItems({ text: 'Logout' });
    await logoutItems[0].click();
    fixture.detectChanges();

    expect(authServiceStub.logout).toHaveBeenCalledTimes(1);
    expect(component.isLoggingOut).toBe(true);
    expect(
      (fixture.nativeElement.querySelector('.user-menu-trigger') as HTMLButtonElement).disabled
    ).toBe(true);

    logoutRequests[0].error({ status: 503 });
    await fixture.whenStable();
    fixture.detectChanges();

    expect(component.logoutError).toContain('503');
    expect(fixture.nativeElement.querySelector('.logout-error')?.textContent).toContain('503');
    expect(fixture.nativeElement.querySelector('.user-menu-trigger')?.textContent).toContain(
      'Alice Example'
    );
    expect(component.isLoggingOut).toBe(false);
    expect(
      (fixture.nativeElement.querySelector('.user-menu-trigger') as HTMLButtonElement).disabled
    ).toBe(false);

    await userMenu.open();
    const retryItems = await userMenu.getItems({ text: 'Logout' });
    await retryItems[0].click();
    fixture.detectChanges();

    expect(authServiceStub.logout).toHaveBeenCalledTimes(2);
    expect(component.isLoggingOut).toBe(true);
    expect(
      (fixture.nativeElement.querySelector('.user-menu-trigger') as HTMLButtonElement).disabled
    ).toBe(true);
  });
});

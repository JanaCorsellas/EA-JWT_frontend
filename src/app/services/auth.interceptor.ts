// src/app/services/auth.interceptor.ts
import { HttpEvent, HttpHandlerFn, HttpRequest } from '@angular/common/http';
import { inject } from '@angular/core';
import { AuthService } from './auth.service';
import { Router } from '@angular/router';
import { ToastrService } from 'ngx-toastr';
import { Observable, throwError, from, switchMap, catchError } from 'rxjs';

export function jwtInterceptor(req: HttpRequest<unknown>, next: HttpHandlerFn): Observable<HttpEvent<unknown>> {
  const authService = inject(AuthService);
  const router = inject(Router);
  const toastr = inject(ToastrService);

  // No interceptamos la petición de refresh token
  if (req.url.includes('/auth/refresh')) {
    return next(req);
  }
  
  const token = localStorage.getItem('access_token');
  
  // Si no hay token o está expirado y tenemos refresh token, intentamos refrescar
  if (authService.isTokenExpired() && localStorage.getItem('refresh_token')) {
    return from(authService.refreshToken()).pipe(
      switchMap(() => {
        // Volvemos a intentar con el nuevo token
        const newToken = localStorage.getItem('access_token');
        const clonedReq = req.clone({
          setHeaders: {
            Authorization: `Bearer ${newToken}`
          }
        });
        return next(clonedReq);
      }),
      catchError((refreshError) => {
        // Si falla el refresh, mandamos al login
        authService.logout();
        router.navigate(['/login']);
        toastr.error('Su sesión ha expirado. Por favor, inicie sesión nuevamente.');
        return throwError(() => refreshError);
      })
    );
  }
  
  // Si hay token, lo añadimos a la petición
  if (token) {
    req = req.clone({
      setHeaders: {
        Authorization: `Bearer ${token}`
      }
    });
  }

  // Continuamos con la petición y manejamos el error 401
  return next(req).pipe(
    catchError((error) => {
      if (error.status === 401) {
        localStorage.removeItem('access_token');
        toastr.error(
          'Su sesión ha expirado. Por favor, inicie sesión nuevamente.',
          'Sesión Expirada'
        );
        router.navigate(['/login']);
      }
      return throwError(() => error);
    })
  );
}
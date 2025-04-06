import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable, throwError, of } from 'rxjs';
import { catchError, tap } from 'rxjs/operators';
import { jwtDecode } from 'jwt-decode';

@Injectable({
  providedIn: 'root'
})
export class AuthService {
  private apiUrl = "http://localhost:9000/api/auth";
  
  constructor(private http: HttpClient) { }
  
  login(credentials: { email: string; password: string }): Observable<any> {
    return this.http.post(`${this.apiUrl}/login`, credentials).pipe(
      tap((response: any) => {
        // Guardar ambos tokens
        localStorage.setItem('access_token', response.token);
        localStorage.setItem('refresh_token', response.refreshToken);
      })
    );
  }

  loginWithGoogle(): void {
    window.location.href = `${this.apiUrl}/google`;
  }

  handleGoogleCallback(token: string): Observable<any> {
    localStorage.setItem('access_token', token);
    // El backend debería también devolver un refresh token
    // Si no lo hace ahora, deberías modificarlo
    return of({ success: true, token: token });
  }

  // Nueva función para refrescar token
  refreshToken(): Observable<any> {
    const refreshToken = localStorage.getItem('refresh_token');
    
    if (!refreshToken) {
      return throwError(() => new Error('No refresh token available'));
    }
    
    return this.http.post(`${this.apiUrl}/refresh`, { refreshToken }).pipe(
      tap((response: any) => {
        localStorage.setItem('access_token', response.token);
      }),
      catchError(error => {
        this.logout(); // Si falla, logout
        return throwError(() => error);
      })
    );
  }

  // Verificar si el token actual está expirado
  isTokenExpired(): boolean {
    const token = localStorage.getItem('access_token');
    if (!token) return true;
    
    try {
      const decoded: any = jwtDecode(token);
      const expirationTime = decoded.exp * 1000; // Convertir a milisegundos
      return Date.now() >= expirationTime;
    } catch (error) {
      return true;
    }
  }

  // Obtener datos del token
  getTokenData(): any {
    const token = localStorage.getItem('access_token');
    if (!token) return null;
    
    try {
      return jwtDecode(token);
    } catch (error) {
      return null;
    }
  }

  isAuthenticated(): boolean {
    if (this.isTokenExpired()) {
      // Si hay refresh token, intentamos autenticación silenciosa
      const refreshToken = localStorage.getItem('refresh_token');
      if (refreshToken) {
        // En un caso real, aquí implementarías lógica para verificar 
        // si el refresh token es válido sin hacer una petición HTTP
        return true;
      }
      return false;
    }
    return true;
  }

  logout(): void {
    localStorage.removeItem('access_token');
    localStorage.removeItem('refresh_token');
  }
}
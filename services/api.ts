import axios, { AxiosError } from "axios";
import { parseCookies, setCookie } from 'nookies'
import { SignOut } from "../contexts/AuthContext";
import { AuthTokenError } from "./errors/AuthTokenError";

let isRefreshing = false;
let failedRequestQueue = [];

export function setupAPIClient(ctx = undefined) {
    let cookies = parseCookies(ctx);

    const api = axios.create({
        baseURL: 'http://localhost:3333',
        headers: {
            Authorization: `Bearer ${cookies['nextauth.token']}`
        }
    });
    
    api.interceptors.response.use(response => {
        return response;
    }, (error: AxiosError) => {
        if (error.response.status === 401 ) {
            if (error.response.data?.code === 'token.expired') {
                // Removendo o token
                cookies = parseCookies(ctx);
    
                const { 'nextauth.refreshtoken': refreshToken } = cookies;
                const originalConfig = error.config
    
                if (!isRefreshing) {
                    isRefreshing = true
    
                    api.post('/refresh', {
                        refreshToken,
                    }).then(response => {
                        const { token } = response.data;
        
                        setCookie(ctx, 'nextauth.token', token, {
                            maxAge: 60 * 60 * 24 * 30, // 30 days
                            path: '/' 
                        })
            
                        setCookie(ctx, 'nextauth.refreshtoken', response.data.refreshToken, {
                            maxAge: 60 * 60 * 24 * 30, // 30 days
                            path: '/' 
                        })
        
                        api.defaults.headers['Authorization'] = `Bearer ${token}`;
    
                        failedRequestQueue.forEach(request => request.onSuccess(token))
                        failedRequestQueue = []
                    }).catch(err => {
                        failedRequestQueue.forEach(request => request.onFailed(err))
                        failedRequestQueue = []
    
                        if (process.browser) {
                            SignOut();
                        }
                    }).finally(() => {
                        isRefreshing = false
                    });
                }
    
                return new Promise((resolve, reject) => {
                    failedRequestQueue.push({
                        onSuccess: (token: String) => {
                            originalConfig.headers['Authorization'] = `Bearer ${token}`
    
                            resolve(api(originalConfig))
                        },
                        onFailed: (err: AxiosError) => {
                            reject(err)
                        } 
                    })
                })
            } else {
                // Desligando o usuário
                if (process.browser) {
                    SignOut();
                } else {
                    return Promise.reject(new AuthTokenError())
                }                
            }
        }
        return Promise.reject(error);
    });

    return api;
}
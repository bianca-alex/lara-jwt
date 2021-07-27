<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use \Tymon\JWTAuth\Http\Middleware\BaseMiddleware;
use \Tymon\JWTAuth\Exceptions\TokenExpiredException;

class RefreshToken extends BaseMiddleware
{
    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure  $next
     * @return mixed
     */
    public function handle(Request $request, Closure $next)
    {
        $this->checkForToken($request);
        try {
            if (! $this->auth->parseToken()->authenticate()) {
                throw new UnauthorizedHttpException('jwt-auth', 'User not found');
            }
        } catch (TokenExpiredException $e) {
            //throw new UnauthorizedHttpException('jwt-auth', $e->getMessage(), $e, $e->getCode());
            return response()->json(['message' => 'Token expired.']);
        }
    	return $next($request);
    }
}

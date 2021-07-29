<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use \Tymon\JWTAuth\Http\Middleware\BaseMiddleware;
use \Tymon\JWTAuth\Exceptions\TokenExpiredException;
use Tymon\JWTAuth\Exceptions\TokenBlacklistedException;

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
            if (!$this->auth->parseToken()->authenticate()) {
                return response()->json(['message' => 'User not found.'], 401);
            }
            return $next($request); 
        } catch (TokenExpiredException $e) {
            try{
                $refresh_token = $this->auth->refresh();
                return response()->json(['message' => 'Token expired.', 'refresh_token' => $refresh_token], 200);
            } catch (TokenExpiredException $e) {
                return response()->json(['message' => 'Please login in.'], 401);
            } catch (tokenblacklistedexception $ex) {
                return response()->json(['message' => 'token is invalid.'], 401);
            }
            /*auth('api')->onceUsingId($this->auth->manager()->getPayloadFactory()->buildClaimsCollection()->toPlainArray()['sub']);
            return $this->setAuthenticationHeader($next($request), $refresh_token);*/
        } catch (tokenblacklistedexception $ex) {
            return response()->json(['message' => 'token is invalid.'], 401);
        }
    }
}

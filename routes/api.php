<?php

$api = app('Dingo\Api\Routing\Router');
$api->version('v1', function ($api) {

    $api->get('/dingo',function(){
        return "hello world";
    });


    $api->get('/no_access', function () {
        return "no_access";
    });

    $api->group(['middleware' => 'auth:api', 'bindings'], function ($api) {
        $api->get('my', function () {
            return 'oauth my';
        });
    });
});

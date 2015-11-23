/*
 * Copyright (C) 2015 Daniel Straub, Sandro Sonntag, Christian Brandenstein, Francis Pouatcha (sso@adorsys.de, dst@adorsys.de, cbr@adorsys.de, fpo@adorsys.de)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
var app = angular.module("demo", ["oauth2", "ui.router"]);

app.config(function ($stateProvider, $urlRouterProvider, $locationProvider) {
    $locationProvider.html5Mode(false);

    $urlRouterProvider.otherwise('/home');

    $stateProvider.state('home', {
        url: '/home',
        templateUrl: '/app/demo/home.html',
    }).state('voucher', {
        url: '/voucher',
        templateUrl: '/app/demo/voucher.html',
        controller: 'VoucherCtrl',
        restricted: true
    }).state('login', {
        url: '/login?requestedUrl',
        templateUrl: '/app/demo/login.html',
        controller: 'LoginCtrl'
    }).state('logout', {
        url: '/logout',
        templateUrl: '/app/demo/logout.html',
        controller: 'LogoutCtrl'
    });

});

app.constant("apiUrl", "http://localhost:8280/app");

app.run(function (oauthService, $http, $state, $rootScope, $location, apiUrl) {

    oauthService.rngUrl   = apiUrl + "/api/random";
    oauthService.loginUrl = "http://localhost:8280/oauth/auth";
    //oauthService.redirectUri = location.origin + "/app/index.html";
    oauthService.redirectUri = location.origin + "/app/callback.html";
    
    oauthService.clientId = "sample";
    oauthService.scope    = "voucher";

    $rootScope.$on("$stateChangeStart", function (event, toState, toParams, fromState, fromParams) {

        
        if (toState.restricted && !oauthService.getIsLoggedIn()) {
            event.preventDefault();
            var requestedUrl = $state.href(toState, toParams);
            $state.transitionTo("login", { requestedUrl: requestedUrl });
        }

    });

    if (oauthService.getIsLoggedIn() || oauthService.tryLogin()) {
        $http.defaults.headers.common['Authorization'] = 'Bearer ' + oauthService.getAccessToken();
        
        if (oauthService.state) {
            $location.url(oauthService.state.substr(1)); // führendes # abschneiden
        }
    }

    $rootScope.global = {};
    $rootScope.global.logOut = function () {
        oauthService.logOut();
        $state.go("login");
    }

});

app.controller("VoucherCtrl", function ($scope, $http, oauthService, apiUrl) {

    $scope.model = {};

    $scope.model.message = "";
    $scope.model.buyVoucher = function () {
        $http
            .post(apiUrl + "/api/voucher?betrag=150", null)
            .then(function (result) {
                $scope.model.message = result.data;
        })
        .catch(function (message) {
                $scope.model.message = "Was not able to receive new voucher: " + message.status;
        });
    }

    $scope.refresh = function () {
        oauthService
            .tryRefresh()
            .then(function () {
                $scope.model.message = "Got Token!";
                $http.defaults.headers.common['Authorization'] = 'Bearer ' + oauthService.getAccessToken();
            })
            .catch(function () {
                $scope.model.message = "Error receiving new token!";
            });
    }

});

app.controller("LoginCtrl", function ($scope, $stateParams, oauthService, $http) {

    $scope.model = {
        requestedUrl: $stateParams.requestedUrl,
        callback: function(requestedUrl) {
            $http.defaults.headers.common['Authorization'] = 'Bearer ' + oauthService.getAccessToken();
        }
    };

});

app.controller("LogoutCtrl", function (oauthService) {
    oauthService.logOut();
})
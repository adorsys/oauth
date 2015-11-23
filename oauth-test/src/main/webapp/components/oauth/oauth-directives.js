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
﻿(function () {

    var oauth2 = angular.module("oauth2");

    oauth2.directive("oauthLoginButton", function (oauthService, $log) {
        return {
            scope: {
                state: "="
            },
            link: function (scope, element, attrs) {
                oauthService.createLoginUrl(scope.state).then(function (url) {
                    element.attr("onclick", "location.href='" + url + "'");
                })
                .catch(function (error) {
                    $log.error("oauthLoginButton-directive error");
                    $log.error(error);
                    throw error;
                });
            }
        };
    });

    oauth2.directive("oauthLoginForm", function (oauthService, $location, $timeout) {
        return {
            scope: {
                callback: "&",
                state: "="
            },
            link: function (scope, element, attrs) {

                window.onOAuthCallback = function (requestedUrl) {
                    if (scope.callback) {
                        scope.callback();
                    }

                    if (requestedUrl) {
                        $timeout(function () {
                            $location.url(requestedUrl.substr(1));
                        }, 0);
                    }
                }

                oauthService.createLoginUrl(scope.state).then(function (url) {
                    var html = "<iframe src='" + url + "' height='400' width='400' id='oauthFrame' class='oauthFrame'></iframe>";
                    element.html(html);
                }).catch(function (error) {
                    $log.error("oauthLoginForm-directive error");
                    $log.error(error);
                });
            }
        };
    });

})();
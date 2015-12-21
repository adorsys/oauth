<%--

    Copyright (C) 2015 Daniel Straub, Sandro Sonntag, Christian Brandenstein, Francis Pouatcha (sso@adorsys.de, dst@adorsys.de, cbr@adorsys.de, fpo@adorsys.de)

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

            http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.

--%>
<%@ page contentType="text/html;charset=UTF-8" language="java" session="false"%>
<!doctype html>
<html lang="en" ng-app="oauthLogin">
<head>
<meta charset="utf-8">
<meta http-equiv="X-UA-Compatible" content="IE=edge">
<meta name="viewport" content="width=device-width, minimum-scale=1.0, maximum-scale=1.0, user-scalable=no"/>
<meta name="apple-mobile-web-app-capable" content="yes"/>
<meta name="apple-mobile-web-app-status-bar-style" content="black"/>
<link rel="shortcut icon" href="/oauth-login-theme/img/favicon.ico" />
<link rel="stylesheet" href="/oauth-login-theme/css/application.css"/>
<script src="/oauth-login-theme/js/custom.js"></script>
<title translate>title</title>
<script>
    var bouncer = {
        loginpage : '/oauth-login-theme/login_template.html',
        translationPath : '/oauth-login-theme/i18n/translate-'
    }
</script>
</head>
<body ng-cloak ng-init="loginUrl = '${requestScope['javax.servlet.forward.request_uri']}?${pageContext.request.queryString}'; loginError = ${requestScope.oauthloginerror == true}">

<div ng-view></div>
<script src="${pageContext.request.contextPath}/components/angularjs/angular.js"></script>
<script src="${pageContext.request.contextPath}/components/angular-route/angular-route.min.js"></script>
<script src="${pageContext.request.contextPath}/components/angular-translate/angular-translate.min.js"></script>
<script src="${pageContext.request.contextPath}/components/angular-translate-loader-static-files/angular-translate-loader-static-files.min.js"></script>
<script src="${pageContext.request.contextPath}/login/app.js"></script>
</body>
</html>

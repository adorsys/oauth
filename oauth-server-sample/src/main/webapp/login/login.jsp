<%@ page contentType="text/html;charset=UTF-8" language="java" session="false"%>
<!doctype html>
<html lang="en" ng-app="oauthLogin">
<head>
<meta charset="utf-8">
<meta http-equiv="X-UA-Compatible" content="IE=edge">
<meta name="viewport" content="width=device-width, minimum-scale=1.0, maximum-scale=1.0, user-scalable=no"/>
<meta name="apple-mobile-web-app-capable" content="yes"/>
<meta name="apple-mobile-web-app-status-bar-style" content="black"/>
<link rel="apple-touch-icon" href="/oauth-login-theme/images/apple-touch-icon.png" />
<link rel="shortcut icon" href="/oauth-login-theme/images/favicon.png" />
<link rel="stylesheet" href="/oauth-login-theme/css/bootstrap.css"/>
<link rel="stylesheet" href="/oauth-login-theme/css/application.css"/>
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

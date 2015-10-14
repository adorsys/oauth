angular.module('oauthLogin', ['ngRoute', 'pascalprecht.translate'])
    .config(['$routeProvider',
    function($routeProvider) {
        $routeProvider.
            otherwise({
                templateUrl: bouncer.loginpage
            });
    }]).config(['$translateProvider',
        function ($translateProvider) {
            $translateProvider.useStaticFilesLoader({
                prefix: bouncer.translationPath,
                suffix: '.json'
            });
            $translateProvider.registerAvailableLanguageKeys(["de", "en"]);
            $translateProvider.determinePreferredLanguage();
        }]);
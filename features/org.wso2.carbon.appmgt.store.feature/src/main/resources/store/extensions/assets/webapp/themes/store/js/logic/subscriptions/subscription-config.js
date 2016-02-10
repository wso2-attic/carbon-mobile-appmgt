include('/extensions/assets/webapp/modules/jagg/jagg.jag');

var site = require("/config/store.json");
var isSelfSubEnabled = site.SubscriptionConfiguration.EnableSelfSubscription;
var isEnterpriseSubEnabled = site.SubscriptionConfiguration.EnableEnterpriseSubscription;
var log = new Log("subscription-config.js");

var isSelfSubscriptionEnabled = function () {
    return isSelfSubEnabled;

};

var isEnterpriseSubscriptionEnabled = function () {
    return isEnterpriseSubEnabled;

};

var isMyFavouriteMenu = function () {
    if (!isSelfSubEnabled && !isEnterpriseSubEnabled) {
        return true;
    }
    return false;
};

var getAnonymousApps = function (fn, request, session) {
    var result = [];
    var managers = require('/modules/store.js').storeManagers(request, session);
    var rxtManager = managers.rxtManager;
    var artifactManager = rxtManager.getArtifactManager(type);
    result = artifactManager.find(fn, null);
    return result;
};




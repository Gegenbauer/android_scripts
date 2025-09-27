import Java from "frida-java-bridge";

/*
 * frida_set_language.js
 * Responsible for setting the system language in an Android process.
 */
function setSystemLanguage(language, country) {
    Java.perform(function () {
        let TAG = "setSystemLanguage";
        let Locale = Java.use("java.util.Locale");
        let String = Java.use("java.lang.String");
        if (!language) {
            send({ type: 'error', message: 'Language is not specified.' });
            return;
        }
        if (!country) {
            // country is optional, if not specified, use an empty string
            country = "";
        }
        let languageString = String.$new(language);
        let countryString = String.$new(country);
        var locale = Locale.$new(languageString, countryString);
        send({ type: 'info', message: 'Setting system language to: ' + locale.toString() });
        try {
            let ActivityManagerNative = Java.use("android.app.ActivityManagerNative");
            let activityManager = ActivityManagerNative.getDefault();
            let configuration = activityManager.getConfiguration();
            let LocaleList = Java.use("android.os.LocaleList");
            let localeList = LocaleList.$new([locale]);
            configuration.setLocales(localeList);
            configuration.userSetLocale.value = true;
            activityManager.updatePersistentConfiguration(configuration);
            if (country) {
                send({ type: 'finish', message: 'System language set to: ' + language + '-' + country });
            } else {
                send({ type: 'finish', message: 'System language set to: ' + language });
            }
        } catch (e) {
            send({ type: 'error', message: 'Failed to set system language: ' + e });
        }
    });
}

rpc.exports = {
    setsystemlanguage: setSystemLanguage
};

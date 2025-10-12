import Java from "frida-java-bridge";

function fragmentToString(fragment, deprecatedFragmentExist, androidxFragmentExist) {
    if (fragment == null) {
        return "null";
    }
    try {
        // check whether fragment is compat or deprecated
        let className = fragment.getClass().getName();
        let compatFragmentClass = androidxFragmentExist ? Java.use("androidx.fragment.app.Fragment") : null;
        let deprecatedFragmentClass = deprecatedFragmentExist ? Java.use("android.app.Fragment") : null;
        let System = Java.use("java.lang.System");
        let Integer = Java.use("java.lang.Integer");
        let fragmentInfo = {
            className: "",
            id: -1,
            tag: "",
            hashCodeInHex: "",
            host: null,
            isResumed: false,
            isDeprecated: true
        }
        if (compatFragmentClass && compatFragmentClass.class.isInstance(fragment)) {
            let compatFragment = Java.cast(fragment, Java.use("androidx.fragment.app.Fragment"));
            fragmentInfo = {
                className: className,
                id: compatFragment.getId(),
                tag: compatFragment.getTag(),
                hashCodeInHex: Integer.toHexString(System.identityHashCode(compatFragment)),
                host: compatFragment.getHost(),
                isResumed: compatFragment.isResumed(),
                isDeprecated: false,
            };
        } else if (deprecatedFragmentClass && deprecatedFragmentClass.class.isInstance(fragment)) {
            let deprecatedFragment = Java.cast(fragment, Java.use("android.app.Fragment"));
            fragmentInfo = {
                className: className,
                id: deprecatedFragment.getId(),
                tag: deprecatedFragment.getTag(),
                hashCodeInHex: Integer.toHexString(System.identityHashCode(deprecatedFragment)),
                host: deprecatedFragment.getHost(),
                isResumed: deprecatedFragment.isResumed(),
                isDeprecated: true
            };
        }
        if (!fragmentInfo.isResumed) {
            return ""; // only return resumed fragments
        }
        return `${fragmentInfo.className}{${fragmentInfo.hashCodeInHex}}(id=${fragmentInfo.id},` +
            `tag=${fragmentInfo.tag}, host=${fragmentInfo.host}), isDeprecated=${fragmentInfo.isDeprecated}`;
    } catch (e) {
        return `Fragment{error=${e}}`;
    }
}

/*
 * get_resumed_fragment.js
 * Retrieves all currently resumed fragments in an Android application.
 * Collects all fragments first, then sends them in a single response.
 */
function getResumedFragment(language, country) {
    Java.perform(function () {
        let TAG = "getResumedFragment";
        let resumedFragments = [];
        let completedSearches = 0;
        // check if classes exist
        let deprecatedFragmentManagerExists = false;
        let androidXFragmentManagerExists = false;
        try {
            Java.use("android.app.FragmentManagerImpl");
            deprecatedFragmentManagerExists = true;
        } catch (e) {
            send({ type: 'debug', message: `[${TAG}] Deprecated FragmentManagerImpl class not found.` });
        }
        try {
            Java.use("androidx.fragment.app.FragmentManagerImpl");
            androidXFragmentManagerExists = true;
        } catch (e) {
            send({ type: 'debug', message: `[${TAG}] AndroidX FragmentManagerImpl class not found.` });
        }
        if (!deprecatedFragmentManagerExists && !androidXFragmentManagerExists) {
            send({ type: 'result', message: 'No FragmentManagerImpl classes found.', data: [] });
            return;
        }
        let totalSearches = 0;
        if (deprecatedFragmentManagerExists) totalSearches++;
        if (androidXFragmentManagerExists) totalSearches++;

        function checkAndSendResults() {
            completedSearches++;
            if (completedSearches >= totalSearches) {
                // All searches completed, send collected results
                send({
                    type: 'result',
                    message: `Found ${resumedFragments.length} resumed fragments`,
                    data: resumedFragments
                });
            }
        }

        if (deprecatedFragmentManagerExists) {
            // Search in DeprecatedFragmentManager
            Java.choose("android.app.FragmentManagerImpl", {
                onMatch: function (instance) {
                    try {
                        let fragments = instance.getFragments();
                        let size = fragments.size();
                        send({ type: 'debug', message: `[${TAG}] DeprecatedFragmentManager has ${size} fragments` });
                        for (let i = 0; i < size; i++) {
                            let fragment = fragments.get(i);
                            send({ type: 'debug', message: `[${TAG}] Inspecting fragment: ${fragmentToString(fragment, deprecatedFragmentManagerExists, androidXFragmentManagerExists)}` });
                            if (fragment != null) {
                                let fragmentStr = fragmentToString(fragment, deprecatedFragmentManagerExists, androidXFragmentManagerExists);
                                if (fragmentStr !== "") {
                                    resumedFragments.push(fragmentStr);
                                }
                            }
                        }
                    } catch (e) {
                        send({ type: 'error', message: `[${TAG}] Error while processing DeprecatedFragmentManager: ${e}` });
                    }
                },
                onComplete: function () {
                    send({ type: 'debug', message: `[${TAG}] Completed searching DeprecatedFragmentManager` });
                    checkAndSendResults();
                }
            });
        }

        if (androidXFragmentManagerExists) {
            // Search in AndroidXFragmentManager
            Java.choose("androidx.fragment.app.FragmentManagerImpl", {
                onMatch: function (instance) {
                    try {
                        let fragments = instance.getFragments();
                        let size = fragments.size();
                        send({ type: 'debug', message: `[${TAG}] AndroidXFragmentManager has ${size} fragments` });
                        for (let i = 0; i < size; i++) {
                            let fragment = fragments.get(i);
                            send({ type: 'debug', message: `[${TAG}] Inspecting fragment: ${fragmentToString(fragment, deprecatedFragmentManagerExists, androidXFragmentManagerExists)}` });
                            let fragmentStr = fragmentToString(fragment, deprecatedFragmentManagerExists, androidXFragmentManagerExists);
                            if (fragmentStr !== "") {
                                resumedFragments.push(fragmentStr);
                            }
                        }
                    } catch (e) {
                        send({ type: 'error', message: `[${TAG}] Error while processing AndroidXFragmentManager: ${e}` });
                    }
                },
                onComplete: function () {
                    send({ type: 'debug', message: `[${TAG}] Completed searching AndroidXFragmentManager` });
                    checkAndSendResults();
                }
            });
        }
    });
}

rpc.exports = {
    getresumedfragment: getResumedFragment
};
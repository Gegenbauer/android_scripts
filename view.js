import Java from "frida-java-bridge";

function findFrontMostVisibleViewRoot() {
    let TAG = "findFrontMostVisibleViewRoot";
    // 获取到 WindowManagerGlobal 实例
    let WindowManagerGlobal = Java.use("android.view.WindowManagerGlobal");
    let WindowLayoutParams = Java.use("android.view.WindowManager$LayoutParams");
    let View = Java.use("android.view.View");

    // 获取 WindowManagerGlobal 的实例
    let instance = WindowManagerGlobal.getInstance();

    // 获取实例的 mViews
    let views = instance.mViews.value;

    // 获取 mParams 属性
    let params = instance.mParams.value;

    // 遍历 viewsArray
    let focusedView = null;
    let maxType = -1;
    for (let i = 0; i < views.size(); i++) {
        let view = Java.cast(views.get(i), View);
        let visible = view.getVisibility() === View.VISIBLE.value;
        let windowParams = Java.cast(params.get(i), WindowLayoutParams);
        let windowType = windowParams.type.value;
        if (visible && windowType > maxType) {
            focusedView = view;
            maxType = windowType;
        }
        send({ type: 'debug', message: `View[${i}]: ${view}, Type: ${view.$className}, Visibility: ${visible ? "VISIBLE" : "INVISIBLE"}, Window Type: ${windowType}` });
    }

    send({ type: 'info', message: `Focused View: ${focusedView}, Max Type: ${maxType}` });
    return focusedView;
}

function isAssignableFrom(ins, clazz) {
    return clazz.isInstance(ins)
}

function buildViewList(rootView) {
    let ViewGroup = Java.use("android.view.ViewGroup");
    let result = [];

    function traverse(view) {
        if (!view) return;
        result.push(view);
        if (isAssignableFrom(view, ViewGroup.class)) {
            let group = Java.cast(view, ViewGroup);
            let count = group.getChildCount();
            for (let i = 0; i < count; i++) {
                let child = group.getChildAt(i);
                traverse(child);
            }
        }
    }
    traverse(rootView);
    return result;
}

// traverse view hierarchy to get all views, use BFS
// return a tree of views
function buildViewTree(rootView) {
    let ViewGroup = Java.use("android.view.ViewGroup");

    function buildTree(view) {
        let node = {
            view: view,
            children: []
        };
        if (isAssignableFrom(view, ViewGroup.class)) {
            let group = Java.cast(view, ViewGroup);
            let count = group.getChildCount();
            for (let i = 0; i < count; i++) {
                let child = group.getChildAt(i);
                if (child !== null) {
                    node.children.push(buildTree(child));
                }
            }
        }
        return node;
    }
    return buildTree(rootView);
}

function flattenTree(node) {
    // Recursively flatten the tree into a flat array of views
    let result = [];
    function traverse(n) {
        if (!n) return;
        result.push(n.view);
        if (n.children && n.children.length > 0) {
            for (let i = 0; i < n.children.length; i++) {
                traverse(n.children[i]);
            }
        }
    }
    traverse(node);
    return result;
}

function visibilityToString(visibility) {
    let View = Java.use("android.view.View");
    switch (visibility) {
        case View.VISIBLE.value:
            return "VISIBLE";
        case View.INVISIBLE.value:
            return "INVISIBLE";
        case View.GONE.value:
            return "GONE";
    }
}

function viewToString(view) {
    let TextView = Java.use("android.widget.TextView");
    let ImageView = Java.use("android.widget.ImageView");
    let EditText = Java.use("android.widget.EditText");
    let Button = Java.use("android.widget.Button");
    let System = Java.use("java.lang.System");

    let className = view.$className;
    let hashCode = System.identityHashCode(view);
    let id = view.getId();
    let visibility = view.getVisibility();
    let width = view.getWidth();
    let height = view.getHeight();
    let x = view.getX();
    let y = view.getY();
    let clickable = view.isClickable();
    let enabled = view.isEnabled();
    let focused = view.isFocused();
    let contentDescription = view.getContentDescription();
    let text = "";
    if (isAssignableFrom(view, TextView.class)) {
        let textView = Java.cast(view, TextView);
        text = textView.getText().toString();
    } else if (isAssignableFrom(view, EditText.class)) {
        let editText = Java.cast(view, EditText);
        text = editText.getText().toString();
    } else if (isAssignableFrom(view, Button.class)) {
        let button = Java.cast(view, Button);
        text = button.getText().toString();
    } else if (isAssignableFrom(view, ImageView.class)) {
        let imageView = Java.cast(view, ImageView);
        text = "[ImageView]";
    }

    if (contentDescription) {
        contentDescription = contentDescription.toString();
    } else {
        contentDescription = "";
    }
    if (!text) {
        text = "";
    }

    // get output and ignore empty values
    let parts = [];
    parts.push(`Class: ${className}`);
    parts.push(`Hash: 0x${(hashCode >>> 0).toString(16)}`);
    if (id !== -1) {
        // try to get resource name
        let resName = "";
        try {
            let context = view.getContext();
            let resources = context.getResources();
            resName = resources.getResourceEntryName(id);
        } catch (e) {
            resName = "";
        }
        if (resName) {
            parts.push(`ID: ${resName}`);
        } else {
            parts.push(`ID: ${id}`);
        }
    }
    parts.push(`Visibility: ${visibilityToString(visibility)}`);
    parts.push(`Position: (${x}, ${y})`);
    parts.push(`Size: (${width}x${height})`);
    parts.push(`Clickable: ${clickable}`);
    parts.push(`Enabled: ${enabled}`);
    parts.push(`Focused: ${focused}`);
    if (contentDescription) {
        parts.push(`ContentDescription: "${contentDescription}"`);
    }
    if (text) {
        parts.push(`Text: "${text}"`);
    }

    return parts.join(", ");
}

function getViewsByType(views, type) {
    let clazz = Java.use(type);
    return views.filter(view => isAssignableFrom(view, clazz.class));
}

function treeToString(node, depth) {
    let indent = '  '.repeat(depth);
    let levelInfo = `[L${depth}]`;
    let lines = [indent + levelInfo + ' ' + viewToString(node.view)];
    if (node.children && node.children.length > 0) {
        for (let i = 0; i < node.children.length; i++) {
            lines.push(treeToString(node.children[i], depth + 1));
        }
    }
    return lines.join('\n');
}

function dumpViewHierarchy() {
    let viewRoot = findFrontMostVisibleViewRoot();
    if (!viewRoot) {
        send({ type: 'error', message: 'No visible view found.' });
        return;
    }
    let tree = buildViewTree(viewRoot);
    let treeStr = treeToString(tree, 0);
    send({ type: 'info', message: 'View Hierarchy (tree):\n' + treeStr });
    send({ type: 'finish', message: 'Dump finished' });
}

function dumpViewsByType(type) {
    let viewRoot = findFrontMostVisibleViewRoot();
    if (!viewRoot) {
        send({ type: 'error', message: 'No visible view found.' });
        return;
    }
    let allViews = buildViewList(viewRoot);
    let filteredViews = getViewsByType(allViews, type);
    if (filteredViews.length === 0) {
        send({ type: 'info', message: `No views found of type ${type}.` });
        return;
    }
    let viewStrings = filteredViews.map(view => viewToString(view));
    let result = viewStrings.join('\n');
    send({ type: 'info', message: `Views of type ${type}:\n` + result });
    send({ type: 'finish', message: `Found ${filteredViews.length} views of type ${type}.` });
}

function findMatchingOverload(overloads, args) {
    function convertArg(arg, typeName) {
        if (typeName === 'int' || typeName === 'java.lang.Integer') {
            if (typeof arg === 'number') return Math.trunc(arg);
        }
        if (typeName === 'float' || typeName === 'java.lang.Float') {
            if (typeof arg === 'number') return arg;
        }
        if (typeName === 'double' || typeName === 'java.lang.Double') {
            if (typeof arg === 'number') return arg;
        }
        if (typeName === 'boolean' || typeName === 'java.lang.Boolean') {
            if (typeof arg === 'boolean') return arg;
            if (typeof arg === 'number') return arg !== 0;
        }
        if (typeName === 'java.lang.String') {
            if (typeof arg === 'string') return arg;
            if (typeof arg === 'number' || typeof arg === 'boolean') {
                let String = Java.use('java.lang.String');
                return String.$new(arg);
            }
        }
        if (typeName === 'java.lang.CharSequence') {
            // Accept string, number, boolean, or Java String
            if (typeof arg === 'string') return arg;
            if (typeof arg === 'number' || typeof arg === 'boolean') {
                let String = Java.use('java.lang.String');
                return String.$new(arg);
            }
            // Accept Java String or CharSequence
            if (arg && typeof arg.$className === 'string' && (arg.$className === 'java.lang.String' || arg.$className === 'java.lang.CharSequence')) {
                return arg;
            }
        }
        // Allow null/undefined for any reference type
        if ((arg === null || arg === undefined) && !typeName.match(/^(int|float|double|boolean)$/)) {
            return null;
        }
        // Fallback: allow any for object
        if (typeName === 'java.lang.Object') {
            return arg;
        }
        // If not matched, return a special marker
        return Symbol('no-match');
    }
    overloadLoop:
    for (let i = 0; i < overloads.length; i++) {
        let o = overloads[i];
        if (o.argumentTypes.length !== args.length) continue;
        let convertedArgs = [];
        for (let j = 0; j < args.length; j++) {
            let typeName = o.argumentTypes[j].className;
            let conv = convertArg(args[j], typeName);
            if (typeof conv === 'symbol') {
                continue overloadLoop;
            }
            convertedArgs.push(conv);
        }
        return { overload: o, convertedArgs };
    }
    return null;
}

function callViewMethod(viewHash, methodName, ...args) {
    let System = Java.use("java.lang.System");
    let viewRoot = findFrontMostVisibleViewRoot();
    if (!viewRoot) {
        send({ type: 'error', message: 'No visible view found.' });
        send({ type: 'finish', message: 'Method call finished.' });
        return;
    }
    let allViews = buildViewList(viewRoot);
    let targetView = allViews.find(v => System.identityHashCode(v) === viewHash);
    if (!targetView) {
        send({ type: 'error', message: `No view found with hash 0x${(viewHash >>> 0).toString(16)}` });
        send({ type: 'finish', message: 'Method call finished.' });
        return;
    }

    try {
        args = args.filter(arg => arg !== undefined && arg !== null);
        send({ type: 'debug', message: `args: ${JSON.stringify(args)}, args.length: ${args.length}` });
        send({ type: 'debug', message: `Looking for method ${methodName} with args: ${args}` });
        targetView = Java.cast(targetView, Java.use(targetView.$className));
        const methodOverloads = targetView[methodName].overloads;
        const match = findMatchingOverload(methodOverloads, args);
        if (!match) {
            let overloadSigs = methodOverloads.map(o => o.argumentTypes.map(t => t.className).join(", ")).join(" | ");
            send({ type: 'error', message: `Method ${methodName} with ${args.length} arguments not found. Overloads: ${overloadSigs}` });
            send({ type: 'finish', message: 'Method call finished.' });
            return;
        }
        Java.scheduleOnMainThread(() => {
            try {
                let result = match.overload.apply(targetView, match.convertedArgs);
                send({ type: 'info', message: `Method ${methodName} called on view. Result: ${result}` });
            } catch (e) {
                send({ type: 'error', message: `Error calling method ${methodName} on main thread: ${e.message}` });
            }
            send({ type: 'finish', message: 'Method call finished.' });
        });
        return;
    } catch (e) {
        send({ type: 'error', message: `Error calling method ${methodName}: ${e.message}` });
    }
    send({ type: 'finish', message: 'Method call finished.' });
}

rpc.exports = {
    dumpviewhierarchy: dumpViewHierarchy,
    dumpviewsbytype: dumpViewsByType,
    callviewmethod: callViewMethod
};

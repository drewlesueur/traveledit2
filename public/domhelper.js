var domhelper = (function () {
    var currNode
    var stack = []
    var s = function(nodeName, attrs, contents) {
        if (nodeName[0] == "/") {
            if (parent = stack.pop()) parent.appendChild(currNode)
            var c = currNode
            currNode = parent
            return c
        }   
        if (typeof attrs === "string" || typeof attrs === "number" || attrs instanceof HTMLElement || typeof attrs === "function" || typeof attrs == "boolean" || attrs === null) {
            contents = attrs
            attrs = null
        }   
        if (nodeName == "text") {
            var node = document.createTextNode(contents)
            currNode && currNode.appendChild(node)
            return node
        }
        if (!nodeName) {
            var node = document.createDocumentFragment(nodeName)
        } else {
            var node = document.createElement(nodeName)
        }
        for (k in attrs) {
            if (k.slice(0, 2) == "on") {
                node.addEventListener(k.slice(2), attrs[k])
                continue
            } else if (k == "style") {
                node.style.cssText = attrs[k]
                continue
            }   
            node.setAttribute(k, attrs[k])
        }   
        if (typeof contents === "function") {
            stack.push(currNode)
            currNode = node
            contents(node)
            currNode = stack.pop()
            currNode && currNode.appendChild(node)
            return node
        }   
        if (typeof contents != "undefined") {
            if (typeof contents != "object") contents = document.createTextNode(contents)
            if (contents !== null) node.appendChild(contents)
            currNode && currNode.appendChild(node)
            return node
        }   
        stack.push(currNode)
        return currNode = node
    }   
    var tags = ["div", "span", "table", "tr", "td", "th", "img", "a", "text", "input", "form", "button", "pre", "h1", "h2", "h3", "iframe", "br", "textarea"]
    var ret = { 
        s: s,
        setNode: function(n) { currNode = n },
        end: function() { return s("/") },
        frag: function(a, c) { return s("", a, c)}
    }   
    var makeFunc = function(tag) {
        return function(a,c) {
            return s(tag, a, c)
        }   
    }   
    for (var i=0; i<tags.length;i++) {
        ret[tags[i]] = makeFunc(tags[i])    
    }   
    return ret 
})()

var {s, div, span, end, text, table, tr, td, th, img, input, form, button, frag, pre, h1, h2, h3, iframe, br, textarea} = domhelper
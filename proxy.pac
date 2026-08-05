// Selective PAC: only VK-related hosts use the local DPI proxy.
// Prefer HTTP PAC (served by the app):
//   http://127.0.0.1:8889/proxy.pac
// Do NOT use Windows "manual proxy for all sites" — that breaks YouTube etc.

function hostMatches(host, domain) {
    host = host.toLowerCase();
    domain = domain.toLowerCase();
    return host === domain || dnsDomainIs(host, "." + domain);
}

function FindProxyForURL(url, host) {
    if (!host) {
        return "DIRECT";
    }

    // Plain hostnames / IPs: never force through proxy
    if (isPlainHostName(host) || shExpMatch(host, "*.local")) {
        return "DIRECT";
    }

    var domains = [
        "vk.com",
        "vk.ru",
        "vk.me",
        "userapi.com",
        "vk-cdn.net",
        "vk-cdn.me",
        "vkuservideo.net",
        "vkuseraudio.net",
        "vkuserlive.net",
        "vk-portal.net",
        "mvk.com",
        "vkontakte.ru",
        "vkontakte.com",
        "vkcc.com",
        "vk.link"
    ];

    for (var i = 0; i < domains.length; i++) {
        if (hostMatches(host, domains[i])) {
            return "PROXY 127.0.0.1:8888";
        }
    }

    return "DIRECT";
}

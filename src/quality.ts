import { crawler_ipRanges, proxy_ipRanges, tor_ipRanges, vpn_ipRanges } from "./app";
import ip from 'ip';

export function isVPN(ipAddress: string) {
    let isVPN = false;
    vpn_ipRanges.forEach((range) => {
        if(isVPN) return;
        if(range == null || range == "") return;
        const isInRange = ip.cidrSubnet(range).contains(ipAddress);
        if (isInRange) {
            isVPN = true;
        }
    })
    return isVPN;
}

export function isTor(ipAddress: string) {
    let isTOR = false;
    tor_ipRanges.forEach((range) => {
        if(isTOR) return;
        if(range == null || range == "") return;
        const isInList = range === ipAddress;
        if (isInList) {
            isTOR = true;
        }
    })
    return isTOR;
}

export function isProxy(ipAddress: string) {
    let isProxy = false;
    proxy_ipRanges.forEach((range) => {
        if(isProxy) return;
        if(range == null || range == "") return;
        const fix = range.split("//")[1];
        const fix2 = fix.split(":")[0];
        if(fix2 === ipAddress) {
            isProxy = true;
        }
    })
    return isProxy;
}

export function isCrawler(ipAddress: string) {
    let isCrawler = false;
    crawler_ipRanges.forEach((range) => {
        if(isCrawler) return;
        if(range == null || range == "") return;
        const isInRange = ip.cidrSubnet(range).contains(ipAddress);
        if (isInRange) {
            isCrawler = true;
        }
    })
    return isCrawler;
}
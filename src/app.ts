import express, { NextFunction, Request, Response } from 'express';
import Quality from './db/schemas/Quality';
import axios from 'axios';
import mongo from './db/mongoose';

const app = express();
const port = 3000;

app.use((req: Request, res: Response, next: NextFunction) => {
	const cip = req.headers['cf-connecting-ip'] || req.headers['x-forwarded-for'] || req.socket.remoteAddress;
	req.cip = Array.isArray(cip) ? cip[0] : cip;
	next();
});
async function checkIp(req: Request, ip: string) {
	console.log('Checking IP:', ip);
	const key = "Hlz1UI4kam2ptTfHTHTmcpEI8mKNj121";
	let vpnStatus;
	const ipDb = Quality;
	const foundIp = await ipDb.findOne({ IP: ip });
	if (foundIp) {
		console.log('IP found in DB');
		vpnStatus = {
			IP: foundIp.IP,
			country: foundIp.country,
			region: foundIp.region,
			city: foundIp.city,
			ISP: foundIp.ISP,
			ASN: foundIp.ASN,
			org: foundIp.org,
			fraud: foundIp.fraud,
			crawler: foundIp.crawler,
			proxy: foundIp.proxy,
			vpn: foundIp.vpn,
			tor: foundIp.tor,
		};
	} else {
		console.log('IP not found in DB, checking IPQS API');
		const resp = await axios.get('https://www.ipqualityscore.com/api/json/ip/'+key+'/'+req.cip+'?strictness=0&allow_public_access_points=true&fast=true&lighter_penalties=false&mobile=false')
		console.log('Done!')
    	let obj = resp.data;
		await ipDb.create({
			IP: req.cip,
			country: obj.country_code,
			region: obj.region,
			city: obj.city,
			ISP: obj.ISP,
			ASN: obj.ASN,
			org: obj.organization,
			fraud: obj.fraud_score,
			crawler: obj.is_crawler,
			proxy: obj.proxy,
			vpn: obj.vpn,
			tor: obj.tor,
		})
		vpnStatus = {
			IP: req.cip,
			country: obj.country,
			region: obj.region,
			city: obj.city,
			ISP: obj.ISP,
			ASN: obj.ASN,
			org: obj.org,
			fraud: obj.fraud_score,
			crawler: obj.crawler,
			proxy: obj.proxy,
			vpn: obj.vpn,
			tor: obj.tor,
		};

	}
	return vpnStatus;
};

app.get('/', async(req: Request, res: Response) => {
    return res.json({
        success: true,
        code: 200,
        data: {
            "message": "This API provides quality and risk assessment for IP addresses.",
            "usage": {
              "/": "Shows this help message.",
              "/check/<ip>": "Returns a JSON response with risk analysis and metadata for <ip>."
            },
            "responses": {
              "risk_score": "A numerical representation of the IP’s risk level.",
              "type": "Identifies the IP type (e.g., residential, VPN, proxy, datacenter).",
              "blacklist_status": "Indicates whether the IP is listed in known blacklists.",
              "geo_info": "Provides country, city, and ISP details."
            },
            "authentication": "Requests must include an API key in the Authorization header.",
            "additional_info": "For rate limits, authentication, and additional details, refer to the documentation.",
            "links": {
              "source_code": "GitHub Link",
              "documentation": "Docs Link"
            },
			"privacy": "This API stores IP addresses and risk data for analysis and reporting purposes. If you have concerns about privacy or data security, please contact me at cam@expx.dev. If you would like your IP address removed from the database, please provide the IP address and reason for removal in your message. Do note, however, it will be re-stored if the IP is queried again. If you would like to opt out of data storage, please include that in your message as well. This will block any queries for your IP address in the future, and prevent any programs from accessing your data.",
        },
		your_example: await checkIp(req, req.cip)
    })
});

app.get('/check/:ip', async(req: Request, res: Response) => {
	const ip = req.params.ip;
	const vpnStatus = await checkIp(req, ip);
	return res.json({
		success: true,
		code: 200,
		data: vpnStatus
	})
});

(async() => {
	await mongo();
	app.listen(port, '0.0.0.0', () => console.log(`Server started on http://localhost:${port}`));
})()


declare module 'express-serve-static-core' {
	interface Request {
		cip: string;
		vpnStatus: {
			vpn: boolean;
			proxy: boolean;
			tor: boolean;
			fraud: number;
			crawler: boolean;
			bot: boolean;
		};
	}
}
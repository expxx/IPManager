import express, { NextFunction, Request, Response } from 'express';
import axios from 'axios';
import mongo from './db/mongoose';
import Quality from './db/schemas/Quality';
import APIKey from './db/schemas/APIKey';
import Blocks from './db/schemas/Blocks';
import morgan from 'morgan';
import crypto from 'crypto';

const app = express();
const port = parseInt(process.env.SERVER_PORT) || 3000;

async function isAuthenticated(req: Request) {
	const key = req.headers['Authorization'] || req.query.key;
	if (!key) return false;
	const foundKey = await APIKey.findOne({ key: key });
	if (!foundKey) return false;
	foundKey.usage.requests++;
	await foundKey.save();
	return true;
}

app.use(morgan('dev'));
app.use((req: Request, res: Response, next: NextFunction) => {
	const cip = req.headers['cf-connecting-ip'] || req.headers['x-forwarded-for'] || req.socket.remoteAddress;
	req.cip = Array.isArray(cip) ? cip[0] : cip;
	next();
});

async function checkIp(req: Request, ip: string) {
	const isBlocked = await Blocks.findOne({ IPHash: crypto.createHash('sha256').update(ip).digest('hex') });
	if (isBlocked) {
		return {
			IP: crypto.createHash('sha256').update(ip).digest('hex'),
			blocked: true,
			message: 'Your IP is blocked and cannot be queried or stored. You cannot access this site. Please contact cam@expx.dev if you want to unblock your IP.'
		}
	}
	console.log('Checking IP:', ip);
	const key = process.env.IPQS_KEY;
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
		const resp = await axios.get('https://www.ipqualityscore.com/api/json/ip/'+key+'/'+ip+'?strictness=0&allow_public_access_points=true&fast=true&lighter_penalties=false&mobile=false')
		console.debug(resp.data);
		console.log('Done!')
    	let obj = resp.data;
		await ipDb.create({
			IP: ip,
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
			IP: ip,
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
function middleIpCheck() {
	return async(req: Request, res: Response, next: NextFunction) => {
		const ip = req.cip;
		const vpnStatus = await checkIp(req, ip);
		req.vpnStatus = vpnStatus;
		next();
	}
}

app.get('/', middleIpCheck(), async(req: Request, res: Response) => {
	const check = await checkIp(req, req.cip);
    res.json({
        success: true,
        code: 200,
        data: {
            "message": "This API provides quality and risk assessment for IP addresses.",
            "usage": {
              "/": "Shows this help message. Does not require authentication.",
              "/check/<ip>": "Returns a JSON response with risk analysis and metadata for <ip>. Requires authentication.",
			  "/query/<ip>": "Returns a JSON response with risk analysis and metadata for <ip> if the IP is in the database. If not, it will return a 404 error. Does not require authentication.",
            },
            "responses": {
			  "IP": "The IP address being queried.",
			  "country": "The country of the IP address.",
			  "region": "The region of the IP address.",
			  "city": "The city of the IP address.",
			  "ISP": "The Internet Service Provider of the IP address.",
			  "ASN": "The Autonomous System Number of the IP address.",
			  "org": "The organization of the IP address.",
			  "fraud": "The fraud score of the IP address.",
			  "crawler": "Whether the IP address is a crawler.",
			  "proxy": "Whether the IP address is a proxy.",
			  "vpn": "Whether the IP address is a VPN.",
			  "tor": "Whether the IP address is a Tor node."
            },
            "authentication": "Requests must include an API key in the Authorization header.",
            "additional_info": "For rate limits, authentication, and additional details, refer to the documentation.",
            "links": {
              "source_code": "GitHub Link",
              "documentation": "Docs Link"
            },
			"privacy": "This API stores IP addresses and risk data for analysis and reporting purposes. If you have concerns about privacy or data security, please contact me at cam@expx.dev. If you would like your IP address removed from the database, please provide the IP address and reason for removal in your message. Do note, however, it will be re-stored if the IP is queried again. If you would like to opt out of data storage, please include that in your message as well. This will block any queries for your IP address in the future, and prevent any programs from accessing your data.",
			"storage": "Upon visiting this site, any any path it follows, your IP is queried through our detection methods. This data is stored in a secure database for analysis and reporting purposes.",
			"deletion": "You can delete your IP from our database by visiting https://ipmanager.thecavern.dev/delete. You can only delete your IP once every 24 hours.",
			"blocking": "You can block your IP from being queried or stored by visiting https://ipmanager.thecavern.dev/block. This block is permanent and cannot be removed without contacting the site owner. Your IP will never be stored in this database.",
        },
		your_example: check
    })
});

app.get('/check/:ip', middleIpCheck(), async(req: Request, res: Response) => {
	const isAuth = await isAuthenticated(req);
	if(!isAuth) {
		res.status(401).json({
			success: false,
			code: 401,
			message: 'Unauthorized',
			gain: 'Send cam@expx.dev an email to get an API key. Or, join the Discord server at https://discord.gg/APY5fjrM.'
		})
		return;
	}

	const ip = req.params.ip;
	const vpnStatus = await checkIp(req, ip);
	res.json({
		success: true,
		code: 200,
		data: vpnStatus
	})
});

app.get('/query/:ip', middleIpCheck(), async(req: Request, res: Response) => {
	const toCheck = req.params.ip;
	const ipDoc = await Quality.findOne({ IP: toCheck });
	if (!ipDoc) {
		res.status(404).json({
			success: false,
			code: 404,
			message: 'IP not found in database.'
		})
		return;
	}

	res.json({
		success: true,
		code: 200,
		data: ipDoc
	})
});

app.get('/.env', middleIpCheck(), async(req: Request, res: Response) => {
	res.status(200).send('YOU=THOUGHT');
})

app.get('/*', middleIpCheck(), async(req: Request, res: Response) => {
	res.status(200).json({
		success: false,
		code: 404,
		message: 'Route not found.',
		evil: "This route returns 200 to confuse the bots >:)"
	})
})

const rateLimitIps = new Map<string, Date>();
app.get('/delete', async(req: Request, res: Response) => {
	if (rateLimitIps.has(req.cip)) {
		const last = rateLimitIps.get(req.cip);
		const diff = new Date().getTime() - last.getTime();
		if (diff < 86400000) {
			res.status(429).json({
				success: false,
				code: 429,
				message: 'You can only delete your IP once every 24 hours.'
			})
			return;
		}
	}
	rateLimitIps.set(req.cip, new Date());
	const ip = req.cip;
	const ipDoc = await Quality.findOne({ IP: ip });
	if (!ipDoc) {
		res.status(404).json({
			success: false,
			code: 404,
			message: 'IP not found in database.'
		})
		return;
	}

	await Quality.deleteOne({ IP: ip });
	res.json({
		success: true,
		code: 200,
		message: 'IP deleted.',
		important: "Close this tab immediately. Further requests to this site from your IP address will result in the IP being re-stored. You can only delete your IP address once every 24 hours."
	})
});

app.get('/block', async(req: Request, res: Response) => {
	const ip = req.cip;
	const hash = crypto.createHash('sha256').update(ip).digest('hex');
	const blockDoc = await Blocks.findOne({ IPHash: hash });
	if (blockDoc) {
		res.status(403).json({
			success: false,
			code: 403,
			message: 'Your IP is already blocked and cannot be queried or stored.',
			important: 'This block is permanent and cannot be removed without contacting the site owner. Your IP will never be stored in this database.'
		})
		return;
	} else {
		await Blocks.create({ IPHash: hash });
		res.json({
			success: true,
			code: 200,
			message: 'Your IP has been blocked and cannot be queried or stored.',
			important: 'This block is permanent and cannot be removed without contacting the site owner. Your IP will never be stored in this database.'
		})
	}
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
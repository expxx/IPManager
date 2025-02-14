import express, { NextFunction, Request, Response } from 'express';
import axios from 'axios';
import morgan from 'morgan';
import crypto from 'crypto';
import ip from 'ip';
import mongo from './db/mongoose';
import Quality from './db/schemas/Quality';
import APIKey from './db/schemas/APIKey';
import Blocks from './db/schemas/Blocks';
import { isVPN, isProxy, isCrawler, isTor } from './quality';

export const vpn_ipRanges = [];
export const tor_ipRanges = [];
export const proxy_ipRanges = [];
export const crawler_ipRanges = [];

interface CheckResponse {
	IP: string
	country: string
	region: string
	city: string
	asn: string
	crawler: boolean
	proxy: boolean
	vpn: boolean
	tor: boolean
	bot: boolean
}

const app = express();
const port = parseInt(process.env.SERVER_PORT) || 3000;

/** Middleware for logging requests */
app.use(morgan('dev'));

/** Middleware to extract client IP */
app.use((req: Request, res: Response, next: NextFunction) => {
	const cip = req.headers['cf-connecting-ip'] || req.headers['x-forwarded-for'] || req.socket.remoteAddress;
	req.cip = Array.isArray(cip) ? cip[0] : cip;
	next();
});

/** Authenticate API requests */
async function isAuthenticated(req: Request) {
	const key = req.headers['Authorization'] || req.query.key;
	if (!key) return false;

	const foundKey = await APIKey.findOne({ key });
	if (!foundKey) return false;

	foundKey.usage.requests++;
	await foundKey.save();
	return true;
}

/** Check if an IP is blocked */
async function isIpBlocked(ip: string) {
	const hashedIp = crypto.createHash('sha256').update(ip).digest('hex');
	return await Blocks.findOne({ IPHash: hashedIp });
}

/** Fetch or store IP details */
async function checkIp(ip: string) {
	if (await isIpBlocked(ip)) {
		return {
			IP: crypto.createHash('sha256').update(ip).digest('hex'),
			blocked: true,
			message: 'Your IP is blocked and cannot be queried or stored. Contact cam@expx.dev to unblock.',
		};
	}
	const existingRecord = await Quality.findOne({ IP: ip });

	if (existingRecord) {
		console.log('IP found in DB');
		return existingRecord.toObject();
	}

	const data = await askIp2LocationAPI(ip);

	const newRecord = {
		IP: ip,
		country: data.country_code,
		region: data.region_name,
		city: data.city_name,
		asn: data.asn,
		crawler: isCrawler(ip),
		proxy: isProxy(ip),
		vpn: isVPN(ip),
		tor: isTor(ip),
	} as CheckResponse;

	await Quality.create(newRecord);
	return newRecord;
}

/** Middleware to attach VPN status */
function middleIpCheck() {
	return async (req: Request, res: Response, next: NextFunction) => {
		const ip = req.cip;
		const check = await checkIp(ip);
		if ((check as { IP: string, blocked: boolean }).blocked) {
			res.status(403).json(check);
			return;
		}
		req.vpnStatus = check as CheckResponse;
		next();
	};
}

async function loadRanges() {
	// CIDR format
	console.log('Loading IP ranges...');
	console.debug('Fetching VPN IP ranges...');
	const vpns = await axios.get('https://raw.githubusercontent.com/X4BNet/lists_vpn/refs/heads/main/ipv4.txt');
	// <prefix>://<ip>:<port> format
	console.debug('Fetching proxy IP ranges...');
	const proxies = await axios.get('https://raw.githubusercontent.com/proxifly/free-proxy-list/refs/heads/main/proxies/all/data.txt');
	// RAW IP format
	console.debug('Fetching Tor IP ranges...');
	const tors = await axios.get('https://raw.githubusercontent.com/AlterSolutions/tornodes_lists/refs/heads/main/guards/all_guards_ips');
	// CIDR format
	console.debug('Fetching Google Cloud IP ranges...');
	const googleCloud = await axios.get('https://raw.githubusercontent.com/lord-alfred/ipranges/main/google/ipv4.txt');
	// CIDR format
	console.debug('Fetching Googlebot IP ranges...');
	const goggleBot = await axios.get('https://raw.githubusercontent.com/lord-alfred/ipranges/main/googlebot/ipv4.txt');
	// CIDR format
	console.debug('Fetching BingBot IP ranges...');
	const bingBot = await axios.get('https://raw.githubusercontent.com/lord-alfred/ipranges/main/bing/ipv4.txt');
	// CIDR format
	console.debug('Fetching GPT-3 Bot IP ranges...');
	const gptBot = await axios.get('https://raw.githubusercontent.com/lord-alfred/ipranges/main/openai/ipv4.txt');

	vpn_ipRanges.push(...vpns.data.split('\n'));
	proxy_ipRanges.push(...proxies.data.split('\n'));
	tor_ipRanges.push(...tors.data.split('\n'));
	crawler_ipRanges.push(...googleCloud.data.split('\n'));
	crawler_ipRanges.push(...goggleBot.data.split('\n'));
	crawler_ipRanges.push(...bingBot.data.split('\n'));
	crawler_ipRanges.push(...gptBot.data.split('\n'));
}

async function askIp2LocationAPI(ip: string) {
	const key = process.env.IP2LOCATION_KEY;
	const { data } = await axios.get(`https://api.ip2location.io/?ip=${ip}&key=${key}`);
	return data as { ip: string, country_code: string, country_name: string, region_name: string, city_name: string, latitude: number, longitude: number, zip_code: string, time_zone: string, asn: string, as: string, is_proxy: boolean };
}

/** API Endpoints */
app.get('/', middleIpCheck(), async (req: Request, res: Response) => {
	res.json({
		success: true,
		code: 200,
        data: {
            "message": "This API provides quality and risk assessment for IP addresses.",
            "usage": {
			  "/block": "Blocks your IP address from being queried or stored. Does not require authentication. This block is permanent and cannot be removed without contacting the site owner.",
			  "/delete": "Deletes your IP address from the database. Does not require authentication. Rate limited to once every 24 hours.",
              "/": "Shows this help message. Does not require authentication.",
              "/check/<ip>": "Returns a JSON response with risk analysis and metadata for <ip>. Requires authentication.",
			  "/query/<ip>": "Returns a JSON response with risk analysis and metadata for <ip> if the IP is in the database. If not, it will return a 404 error. Does not require authentication.",
            },
            "responses": {
			  "IP": "The IP address being queried.",
			  "country": "The country of the IP address.",
			  "region": "The region of the IP address.",
			  "city": "The city of the IP address.",
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
			"attributions": {
				"ip2location": "This product includes IP2Location LITE data available from https://ip2location.io. This data is used to provide geolocation information for IP addresses.",
			}
        },
		your_example: req.vpnStatus,
    })
});

app.get('/check/:ip', middleIpCheck(), async (req: Request, res: Response) => {
	if (!(await isAuthenticated(req))) {
		res.status(401).json({
			success: false,
			code: 401,
			message: 'Unauthorized',
			info: 'Email cam@expx.dev for an API key or join the Discord: https://discord.gg/APY5fjrM.',
		});
		return;
	}

	res.json({
		success: true,
		code: 200,
		data: await checkIp(req.params.ip),
	});
});

app.get('/query/:ip', middleIpCheck(), async (req: Request, res: Response) => {
	const ipDoc = await Quality.findOne({ IP: req.params.ip });

	if (!ipDoc) {
		res.status(404).json({
			success: false,
			code: 404,
			message: 'IP not found in database.',
		});
		return;
	}

	res.json({
		success: true,
		code: 200,
		data: ipDoc,
	});
});

/** Fun route to confuse bots */
app.get('/.env', async(req: Request, res: Response) => {
	const ip = await Quality.findOne({ IP: req.cip });
	ip.crawler = true;
	await ip.save();
	res.status(200).send('YOU=THOUGHT')
});

/** Rate limiting map */
const rateLimitIps = new Map<string, Date>();

app.get('/delete', async (req: Request, res: Response) => {
	const lastRequest = rateLimitIps.get(req.cip);
	if (lastRequest && new Date().getTime() - lastRequest.getTime() < 86400000) {
		res.status(429).json({
			success: false,
			code: 429,
			message: 'You can only delete your IP once every 24 hours.',
		});
		return;
	}

	rateLimitIps.set(req.cip, new Date());

	const ipDoc = await Quality.findOne({ IP: req.cip });
	if (!ipDoc) {
		res.status(404).json({
			success: false,
			code: 404,
			message: 'IP not found in database.',
		});
		return;
	}

	await Quality.deleteOne({ IP: req.cip });
	res.json({
		success: true,
		code: 200,
		message: 'IP deleted. Future requests will restore it.',
	});
});

app.get('/block', async (req: Request, res: Response) => {
	const hash = crypto.createHash('sha256').update(req.cip).digest('hex');

	if (await Blocks.findOne({ IPHash: hash })) {
		res.status(403).json({
			success: false,
			code: 403,
			message: 'Your IP is already blocked.',
		});
		return;
	}

	await Blocks.create({ IPHash: hash });
	await Quality.deleteOne({ IP: req.cip });
	res.json({
		success: true,
		code: 200,
		message: 'Your IP has been blocked permanently.',
	});
});

/** Catch-all route */
app.get('/*', async(req, res) => {
	const ip = await Quality.findOne({ IP: req.cip });
	ip.crawler = true;
	await ip.save();
	res.status(200).json({
		success: false,
		code: 404,
		message: 'Route not found.',
		evil: 'This route returns 200 to confuse the bots >:)',
	});
});

/** Start the server */
(async () => {
	await loadRanges();
	await mongo();
	app.listen(port, '0.0.0.0', () => console.log(`Server started on http://localhost:${port}`));
})();

/** Extend Express request object */
declare module 'express-serve-static-core' {
	interface Request {
		cip: string;
		vpnStatus: CheckResponse;
	}
}

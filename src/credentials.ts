import {Metadata} from '@grpc/grpc-js';
import jwt from 'jsonwebtoken';
import {DateTime} from 'luxon';
import {GrpcService, ISslCredentials, sleep, withTimeout} from "./utils";
import {TokenService} from 'yandex-cloud';
import {yandex} from "../proto/bundle";
import IamTokenService = yandex.cloud.iam.v1.IamTokenService;
import ICreateIamTokenResponse = yandex.cloud.iam.v1.ICreateIamTokenResponse;


function makeCredentialsMetadata(token: string, dbName: string): Metadata {
    const metadata = new Metadata();
    metadata.add('x-ydb-auth-ticket', token);
    metadata.add('x-ydb-database', dbName);
    return metadata;
}

export interface IIAmCredentials {
    serviceAccountId: string,
    accessKeyId: string,
    privateKey: Buffer,
    iamEndpoint: string
}

export interface IAuthCredentials {
    sslCredentials: ISslCredentials,
    iamCredentials: IIAmCredentials
}

export interface ITokenService {
    getToken: () => string|undefined;
    initialize?: () => Promise<void>;
}

export interface IAuthService {
    getAuthMetadata: () => Promise<Metadata>,
    sslCredentials?: ISslCredentials
}

export class TokenAuthService implements IAuthService {
    constructor(private token: string, private dbName: string, public sslCredentials?: ISslCredentials) {}

    public async getAuthMetadata(): Promise<Metadata> {
        return makeCredentialsMetadata(this.token, this.dbName);
    }
}

export class IamAuthService extends GrpcService<IamTokenService> implements IAuthService {
    private jwtExpirationTimeout = 3600 * 1000;
    private tokenExpirationTimeout = 120 * 1000;
    private tokenRequestTimeout = 10 * 1000;
    private token: string = '';
    private readonly dbName: string = '';
    private tokenTimestamp: DateTime|null;
    private readonly iamCredentials: IIAmCredentials;

    public readonly sslCredentials?: ISslCredentials;

    constructor(iamCredentials: IIAmCredentials, dbName: string, sslCredentials?: ISslCredentials) {
        super(
            iamCredentials.iamEndpoint,
            'yandex.cloud.iam.v1.IamTokenService',
            IamTokenService,
            sslCredentials
        );
        this.iamCredentials = iamCredentials;
        this.dbName = dbName;
        this.tokenTimestamp = null;

        this.sslCredentials = sslCredentials;
    }

    getJwtRequest() {
        const now = DateTime.utc();
        const expires = now.plus({milliseconds: this.jwtExpirationTimeout});
        const payload = {
            "iss": this.iamCredentials.serviceAccountId,
            "aud": "https://iam.api.cloud.yandex.net/iam/v1/tokens",
            "iat": Math.round(now.toSeconds()),
            "exp": Math.round(expires.toSeconds())
        };
        const options: jwt.SignOptions = {
            algorithm: "PS256",
            keyid: this.iamCredentials.accessKeyId
        };
        return jwt.sign(payload, this.iamCredentials.privateKey, options);
    }

    private get expired() {
        return !this.tokenTimestamp || (
            DateTime.utc().diff(this.tokenTimestamp).valueOf() > this.tokenExpirationTimeout
        );
    }

    private sendTokenRequest(): Promise<ICreateIamTokenResponse> {
        const tokenPromise = this.api.create({jwt: this.getJwtRequest()});
        return withTimeout<ICreateIamTokenResponse>(tokenPromise, this.tokenRequestTimeout);
    }

    private async updateToken() {
        const {iamToken} = await this.sendTokenRequest();
        if (iamToken) {
            this.token = iamToken;
            this.tokenTimestamp = DateTime.utc();
        } else {
            throw new Error('Received empty token from IAM!');
        }
    }

    public async getAuthMetadata(): Promise<Metadata> {
        if (this.expired) {
            await this.updateToken();
        }
        return makeCredentialsMetadata(this.token, this.dbName);
    }
}

export class MetadataAuthService implements IAuthService {
    private tokenService: ITokenService;

    static MAX_TRIES = 5;
    static TRIES_INTERVAL = 2000;

    constructor(private dbName: string, public sslCredentials?: ISslCredentials, tokenService?: ITokenService) {
        this.tokenService = tokenService || new TokenService();
    }

    public async getAuthMetadata(): Promise<Metadata> {
        let token = this.tokenService.getToken();
        if (!token && typeof this.tokenService.initialize === 'function') {
            await this.tokenService.initialize();
            token = this.tokenService.getToken();
        }
        let tries = 0;
        while (!token && tries < MetadataAuthService.MAX_TRIES) {
            await sleep(MetadataAuthService.TRIES_INTERVAL);
            tries++;
            token = this.tokenService.getToken();
        }
        if (token) {
            return makeCredentialsMetadata(token, this.dbName);
        }
        throw new Error(`Failed to fetch access token via metadata service in ${MetadataAuthService.MAX_TRIES} tries!`);
    }
}

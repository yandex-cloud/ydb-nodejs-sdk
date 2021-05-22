import {Metadata} from '@grpc/grpc-js';
import * as grpc from '@grpc/grpc-js';
import * as $protobuf from 'protobufjs';
import _ from 'lodash';
import {Ydb} from '../proto/bundle';
import {MissingOperation, MissingValue, NotFound, StatusCode, TimeoutExpired, YdbError} from "./errors";

import {Endpoint} from './discovery';
import {IAuthService} from './credentials';
import {getVersionHeader} from './version';


export interface Pessimizable {
    endpoint: Endpoint;
}

type ServiceFactory<T> = {
    create(rpcImpl: $protobuf.RPCImpl, requestDelimited?: boolean, responseDelimited?: boolean): T
};

export interface ISslCredentials {
    rootCertificates?: Buffer,
    clientPrivateKey?: Buffer,
    clientCertChain?: Buffer
}

function removeProtocol(entryPoint: string) {
    const re = /^(grpc:\/\/|grpcs:\/\/)?(.+)/;
    const match = re.exec(entryPoint) as string[];
    return match[2];
}

export function withTimeout<T>(promise: Promise<T>, timeoutMs: number): Promise<T> {
    let timeoutId: NodeJS.Timeout;
    const timedRejection: Promise<never> = new Promise((_, reject) => {
        timeoutId = setTimeout(() => {
            reject(new TimeoutExpired(`Timeout of ${timeoutMs}ms has expired`));
        }, timeoutMs);
    });
    return Promise.race([promise.then((result: T) => {
        clearTimeout(timeoutId);
        return result;
    }), timedRejection]);
}

export abstract class GrpcService<Api extends $protobuf.rpc.Service> {
    protected api: Api;

    protected constructor(host: string, private name: string, private apiCtor: ServiceFactory<Api>, sslCredentials?: ISslCredentials) {
        this.api = this.getClient(removeProtocol(host), sslCredentials);
    }

    protected getClient(host: string, sslCredentials?: ISslCredentials): Api {
        const client = sslCredentials ?
            new grpc.Client(host, grpc.credentials.createSsl()) :
            new grpc.Client(host, grpc.credentials.createInsecure());
        const rpcImpl: $protobuf.RPCImpl = (method, requestData, callback) => {
            const path = `/${this.name}/${method.name}`;
            client.makeUnaryRequest(path, _.identity, _.identity, requestData, callback);
        };
        return this.apiCtor.create(rpcImpl);
    }
}

export type MetadataHeaders = Map<string, string>;

export abstract class AuthenticatedService<Api extends $protobuf.rpc.Service> {
    protected api: Api;
    private metadata: Metadata | null = null;

    public headers: MetadataHeaders = new Map([getVersionHeader()]);

    static isServiceAsyncMethod(target: object, prop: string|number|symbol, receiver: any) {
        return (
            Reflect.has(target, prop) &&
            typeof Reflect.get(target, prop, receiver) === 'function' &&
            prop !== 'create'
        );
    }

    protected constructor(
        host: string,
        private name: string,
        private apiCtor: ServiceFactory<Api>,
        private authService: IAuthService
    ) {
        this.api = new Proxy(
            this.getClient(removeProtocol(host), this.authService.sslCredentials),
            {
                get: (target, prop, receiver) => {
                    const property = Reflect.get(target, prop, receiver);
                    return AuthenticatedService.isServiceAsyncMethod(target, prop, receiver) ?
                        async (...args: any[]) => {
                            this.metadata = await this.authService.getAuthMetadata();
                            for (const [name, value] of this.headers) {
                                if (value) {
                                    this.metadata.add(name, value);
                                }
                            }

                            return property.call(receiver, ...args);
                        } :
                        property;
                }
            }
        );
    }

    protected getClient(host: string, sslCredentials?: ISslCredentials): Api {
        const client = sslCredentials ?
            new grpc.Client(host, grpc.credentials.createSsl(sslCredentials.rootCertificates)) :
            new grpc.Client(host, grpc.credentials.createInsecure());
        const rpcImpl: $protobuf.RPCImpl = (method, requestData, callback) => {
            const path = `/${this.name}/${method.name}`;
            if (this.metadata) {
                client.makeUnaryRequest(path, _.identity, _.identity, requestData, this.metadata, callback);
            } else {
                client.makeUnaryRequest(path, _.identity, _.identity, requestData, callback);
            }
        };
        return this.apiCtor.create(rpcImpl);
    }
}

interface AsyncResponse {
    operation?: Ydb.Operations.IOperation | null
}

export function getOperationPayload(response: AsyncResponse): Uint8Array {
    const {operation} = response;

    if (operation) {
        YdbError.checkStatus(operation);
        const value = operation?.result?.value;
        if (!value) {
            throw new MissingValue('Missing operation result value!');
        }
        return value;
    } else {
        throw new MissingOperation('No operation in response!');
    }
}

export function ensureOperationSucceeded(response: AsyncResponse, suppressedErrors: StatusCode[] = []): void {
    try {
        getOperationPayload(response);
    } catch (e) {
        if (suppressedErrors.indexOf(e.constructor.status) > -1) {
            return;
        }

        if (!(e instanceof MissingValue)) {
            throw e;
        }
    }
}

export function pessimizable(_target: Pessimizable, _propertyKey: string, descriptor: PropertyDescriptor) {
    const originalMethod = descriptor.value;
    descriptor.value = async function (this: Pessimizable, ...args: any) {
        try {
            return await originalMethod.call(this, ...args);
        } catch (error) {
            if (!(error instanceof NotFound)) {
                this.endpoint.pessimize();
            }
            throw error;
        }
    };
    return descriptor;
}

export async function sleep(milliseconds: number) {
    await new Promise((resolve) => setTimeout(resolve, milliseconds));
}

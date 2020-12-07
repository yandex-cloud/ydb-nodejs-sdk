import DiscoveryService, {Endpoint} from "./discovery";
import {SessionService, TableClient, PoolSettings} from "./table";
import SchemeService from "./scheme";
import {ENDPOINT_DISCOVERY_PERIOD} from "./constants";
import {IAuthService} from "./credentials";
import {TimeoutExpired} from "./errors";
import getLogger, {Logger} from "./logging";
import SchemeClient from "./scheme";


export interface DriverSettings {
    poolSettings?: PoolSettings;
}

export default class Driver {
    private discoveryService: DiscoveryService;
    private sessionCreators: Map<Endpoint, SessionService>;
    private logger: Logger;

    public tableClient: TableClient;
    public schemeClient: SchemeService;

    constructor(
        private entryPoint: string,
        public database: string,
        public authService: IAuthService,
        public settings: DriverSettings = {}
    ) {
        this.discoveryService = new DiscoveryService(
            this.entryPoint, this.database, ENDPOINT_DISCOVERY_PERIOD, authService
        );
        this.discoveryService.on('removed', (endpoint: Endpoint) => {
            this.sessionCreators.delete(endpoint);
        });
        this.sessionCreators = new Map();
        this.tableClient = new TableClient(this);
        this.schemeClient = new SchemeClient(this);
        this.logger = getLogger();
    }

    public async ready(timeout: number): Promise<boolean> {
        try {
            await this.discoveryService.ready(timeout);
            this.logger.debug('Driver is ready!');
            return true;
        } catch (e) {
            if (e instanceof TimeoutExpired) {
                return false;
            } else {
                throw e;
            }
        }
    }

    public async getEndpoint() {
        return await this.discoveryService.getEndpoint();
    }

    public async destroy(): Promise<void> {
        this.logger.debug('Destroying driver...');
        this.discoveryService.destroy();
        await this.tableClient.destroy();
        await this.schemeClient.destroy();
        this.logger.debug('Driver has been destroyed.');
    }

    public async getSessionCreator(): Promise<SessionService> {
        const endpoint = await this.getEndpoint();
        if (!this.sessionCreators.has(endpoint)) {
            this.sessionCreators.set(endpoint, new SessionService(endpoint, this.authService));
        }
        return this.sessionCreators.get(endpoint) as SessionService;
    }
}

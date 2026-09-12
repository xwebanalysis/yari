import { DOCUMENT } from '@angular/common';
import { Injectable, Inject, signal } from '@angular/core';

export type Lang = 'en' | 'es';

type Entry = Record<Lang, string>;

const DICT: Record<string, Entry> = {
  XWA_MODULE: { en: 'XWA - MODULE', es: 'XWA - MODULO' },
  BACKEND_ONLINE: { en: 'BACKEND ONLINE', es: 'BACKEND EN LINEA' },
  BACKEND_OFFLINE: { en: 'BACKEND OFFLINE', es: 'BACKEND CAIDO' },
  NAV_DISCOVER: { en: 'DISCOVER', es: 'DESCUBRIR' },
  NAV_ENDPOINTS: { en: 'ENDPOINTS', es: 'ENDPOINTS' },
  NAV_FUZZING: { en: 'FUZZING', es: 'FUZZING' },
  NAV_AUTH: { en: 'AUTH', es: 'AUTH' },
  NAV_HISTORY: { en: 'HISTORY', es: 'HISTORIAL' },
  LOADING: { en: 'LOADING...', es: 'CARGANDO...' },
  ERROR: { en: 'ERROR', es: 'ERROR' },
  NONE: { en: 'NONE', es: 'NINGUNO' },
  YES: { en: 'YES', es: 'SI' },
  NO: { en: 'NO', es: 'NO' },
  OPEN: { en: 'OPEN', es: 'ABRIR' },
  DELETE: { en: 'DELETE', es: 'BORRAR' },
  DELETE_ALL: { en: 'DELETE ALL', es: 'BORRAR TODO' },
  REFRESH: { en: 'REFRESH', es: 'RECARGAR' },
  EXPORT_JSON: { en: 'EXPORT JSON', es: 'EXPORTAR JSON' },
  EXPORT_CSV: { en: 'EXPORT CSV', es: 'EXPORTAR CSV' },
  EXPORT_PDF: { en: 'EXPORT PDF', es: 'EXPORTAR PDF' },
  TARGET: { en: 'TARGET', es: 'OBJETIVO' },
  STATUS: { en: 'STATUS', es: 'ESTADO' },
  ANALYSIS: { en: 'ANALYSIS', es: 'ANALISIS' },
  CREATED: { en: 'CREATED', es: 'CREADO' },
  STARTED: { en: 'STARTED', es: 'INICIO' },
  FINISHED: { en: 'FINISHED', es: 'FIN' },
  ERROR_MESSAGE: { en: 'ERROR MESSAGE', es: 'MENSAJE DE ERROR' },
  ENDPOINTS: { en: 'ENDPOINTS', es: 'ENDPOINTS' },
  FINDINGS: { en: 'FINDINGS', es: 'HALLAZGOS' },
  REQUESTS: { en: 'REQUESTS', es: 'PETICIONES' },
  HIGH: { en: 'HIGH', es: 'ALTOS' },
  RESULTS: { en: 'RESULTS', es: 'RESULTADOS' },
  SEV_PASS: { en: 'PASS', es: 'OK' },
  SEV_INFO: { en: 'INFO', es: 'INFO' },
  SEV_LOW: { en: 'LOW', es: 'BAJO' },
  SEV_MEDIUM: { en: 'MEDIUM', es: 'MEDIO' },
  SEV_HIGH: { en: 'HIGH', es: 'ALTO' },
  SEV_CRITICAL: { en: 'CRITICAL', es: 'CRITICO' },
  ST_PENDING: { en: 'PENDING', es: 'PENDIENTE' },
  ST_RUNNING: { en: 'RUNNING', es: 'EJECUTANDO' },
  ST_COMPLETED: { en: 'COMPLETED', es: 'COMPLETADO' },
  ST_ERROR: { en: 'ERROR', es: 'ERROR' },
  ST_CANCELLED: { en: 'CANCELLED', es: 'CANCELADO' },
  ST_ABORTED: { en: 'ABORTED', es: 'ABORTADO' },
  ST_SKIPPED: { en: 'SKIPPED', es: 'OMITIDO' },
  DISCOVER_TITLE: { en: 'API DISCOVERY', es: 'DESCUBRIMIENTO DE API' },
  DISCOVER_SUBTITLE: {
    en: 'OPENAPI / GRAPHQL / GRPC / JS CRAWL - READ ONLY',
    es: 'OPENAPI / GRAPHQL / GRPC / RASTREO JS - SOLO LECTURA',
  },
  DISCOVER_HINT: {
    en: 'Only documented paths are probed. No payloads, no mutations.',
    es: 'Solo se sondean rutas documentadas. Sin payloads, sin mutaciones.',
  },
  TARGET_PLACEHOLDER: { en: 'https://api.example.com', es: 'https://api.example.com' },
  MAX_BUNDLES: { en: 'MAX BUNDLES', es: 'MAX BUNDLES' },
  LIVE_STREAM: { en: 'LIVE STREAM (WS)', es: 'STREAM EN VIVO (WS)' },
  RUN_DISCOVERY: { en: 'RUN DISCOVERY', es: 'EJECUTAR DESCUBRIMIENTO' },
  STOP: { en: 'STOP', es: 'DETENER' },
  DISCOVERY_LOG: { en: 'DISCOVERY LOG', es: 'REGISTRO DE DESCUBRIMIENTO' },
  WAITING_EVENTS: { en: '[ WAITING FOR EVENTS ]', es: '[ ESPERANDO EVENTOS ]' },
  VIEW_ENDPOINTS: { en: 'VIEW ENDPOINTS', es: 'VER ENDPOINTS' },
  VIEW_FUZZING: { en: 'VIEW FUZZING', es: 'VER FUZZING' },
  NO_ANALYSIS_SELECTED: {
    en: 'No analysis selected. Run a discovery or pick one from history.',
    es: 'Sin analisis seleccionado. Ejecuta un descubrimiento o elige uno del historial.',
  },
  ENDPOINTS_TITLE: { en: 'ENDPOINT MAP', es: 'MAPA DE ENDPOINTS' },
  ENDPOINTS_SUBTITLE: {
    en: 'DISCOVERED SURFACE BY PROTOCOL',
    es: 'SUPERFICIE DESCUBIERTA POR PROTOCOLO',
  },
  SELECT_ANALYSIS: { en: 'SELECT ANALYSIS', es: 'SELECCIONAR ANALISIS' },
  LOAD: { en: 'LOAD', es: 'CARGAR' },
  ALL: { en: 'ALL', es: 'TODOS' },
  SEARCH: { en: 'SEARCH', es: 'BUSCAR' },
  SEARCH_PLACEHOLDER: { en: 'path, host or source', es: 'ruta, host o fuente' },
  PROTOCOL: { en: 'PROTOCOL', es: 'PROTOCOLO' },
  METHOD: { en: 'METHOD', es: 'METODO' },
  PATH: { en: 'PATH', es: 'RUTA' },
  HOST: { en: 'HOST', es: 'HOST' },
  AUTH_REQUIRED: { en: 'AUTH', es: 'AUTH' },
  SOURCE: { en: 'SOURCE', es: 'FUENTE' },
  VERSION: { en: 'VERSION', es: 'VERSION' },
  PARAMS: { en: 'PARAMS', es: 'PARAMETROS' },
  NO_ENDPOINTS: { en: '[ NO ENDPOINTS ]', es: '[ SIN ENDPOINTS ]' },
  FUZZING_TITLE: { en: 'SAFE FUZZING', es: 'FUZZING SEGURO' },
  FUZZING_SUBTITLE: {
    en: 'BUDGETED 20 REQUEST PASS - NO EXPLOITATION PAYLOADS',
    es: 'PASE DE 20 PETICIONES - SIN PAYLOADS DE EXPLOTACION',
  },
  SAFETY_NOTE: {
    en: 'Safe mode: max 20 requests, 300-1000ms jitter, aborts on 429/503, read-only methods by default.',
    es: 'Modo seguro: max 20 peticiones, jitter 300-1000ms, aborta en 429/503, metodos de solo lectura por defecto.',
  },
  STRATEGY: { en: 'STRATEGY', es: 'ESTRATEGIA' },
  STRATEGY_SAFE: { en: 'SAFE', es: 'SEGURO' },
  STRATEGY_REFLECT: { en: 'REFLECT', es: 'REFLEXION' },
  STRATEGY_ERROR_BASED: { en: 'ERROR BASED', es: 'POR ERRORES' },
  STRATEGY_AUTHZ_MATRIX: { en: 'AUTHZ MATRIX', es: 'MATRIZ AUTHZ' },
  STRATEGY_RATE_LIMIT: { en: 'RATE LIMIT', es: 'RATE LIMIT' },
  AUTH_TOKEN_OPT: { en: 'AUTH TOKEN (OPTIONAL)', es: 'TOKEN AUTH (OPCIONAL)' },
  AUTH_COOKIE_OPT: { en: 'AUTH COOKIE (OPTIONAL)', es: 'COOKIE AUTH (OPCIONAL)' },
  ALLOW_MUTATIONS: { en: 'ALLOW MUTATIONS (OPT-IN)', es: 'PERMITIR MUTACIONES (OPT-IN)' },
  ALLOW_MUTATIONS_HINT: {
    en: 'Without this, only GET/HEAD/OPTIONS are contacted.',
    es: 'Sin esto, solo se contactan GET/HEAD/OPTIONS.',
  },
  SELECT_ENDPOINTS: { en: 'ENDPOINTS TO TEST', es: 'ENDPOINTS A PROBAR' },
  SELECT_ALL: { en: 'SELECT ALL', es: 'SELECCIONAR TODO' },
  CLEAR: { en: 'CLEAR', es: 'LIMPIAR' },
  RUN_FUZZ: { en: 'RUN FUZZ', es: 'EJECUTAR FUZZ' },
  REQUESTS_SENT: { en: 'REQUESTS SENT', es: 'PETICIONES ENVIADAS' },
  FINDINGS_FOUND: { en: 'FINDINGS FOUND', es: 'HALLAZGOS' },
  ABORTED: { en: 'ABORTED', es: 'ABORTADO' },
  NO_FINDINGS: { en: '[ NO FINDINGS ]', es: '[ SIN HALLAZGOS ]' },
  POC_PAYLOAD: { en: 'POC PAYLOAD', es: 'PAYLOAD POC' },
  EVIDENCE: { en: 'EVIDENCE', es: 'EVIDENCIA' },
  CHECK: { en: 'CHECK', es: 'CHEQUEO' },
  CONFIDENCE: { en: 'CONFIDENCE', es: 'CONFIANZA' },
  CATEGORY: { en: 'CATEGORY', es: 'CATEGORIA' },
  TARGET_URL: { en: 'TARGET URL', es: 'URL OBJETIVO' },
  AUTH_TITLE: { en: 'AUTH TESTING', es: 'TESTING DE AUTH' },
  AUTH_SUBTITLE: {
    en: 'JWT / SESSION / API KEY - PASSIVE FIRST',
    es: 'JWT / SESION / API KEY - PASIVO PRIMERO',
  },
  AUTH_PASSIVE_NOTE: {
    en: 'No brute force, no credential fuzzing. Comparative requests run only with credentials you provide (max 2 endpoints).',
    es: 'Sin fuerza bruta, sin fuzzing de credenciales. Las peticiones comparativas solo corren con credenciales que aportes (max 2 endpoints).',
  },
  RUN_AUTH_TEST: { en: 'RUN AUTH TEST', es: 'EJECUTAR TEST AUTH' },
  MECHANISM: { en: 'MECHANISM', es: 'MECANISMO' },
  RESULT: { en: 'RESULT', es: 'RESULTADO' },
  DETAILS: { en: 'DETAILS', es: 'DETALLES' },
  NO_TESTS: { en: '[ NO AUTH TESTS ]', es: '[ SIN TESTS DE AUTH ]' },
  HISTORY_TITLE: { en: 'ANALYSIS HISTORY', es: 'HISTORIAL DE ANALISIS' },
  HISTORY_SUBTITLE: { en: 'PERSISTED API SCANS', es: 'ESCANEOS DE API PERSISTIDOS' },
  FUZZ_RUNS: { en: 'FUZZ RUNS', es: 'RONDAS FUZZ' },
  AUTH_TESTS: { en: 'AUTH TESTS', es: 'TESTS AUTH' },
  NO_HISTORY: { en: '[ NO ANALYSES ]', es: '[ SIN ANALISIS ]' },
  ANALYSIS_DETAIL: { en: 'ANALYSIS DETAIL', es: 'DETALLE DEL ANALISIS' },
  ENDPOINT: { en: 'ENDPOINT', es: 'ENDPOINT' },
  DETECTED: { en: 'DETECTED', es: 'DETECTADO' },
  CVSS: { en: 'CVSS', es: 'CVSS' },
  REQUESTS_SHORT: { en: 'REQ', es: 'PET' },
  GRPC_MODE: { en: 'GRPC MODE', es: 'MODO GRPC' },
  BUNDLES_SCANNED: { en: 'BUNDLES SCANNED', es: 'BUNDLES ESCANEADOS' },
  CONFIRM_DELETE: { en: 'DELETE THIS ANALYSIS?', es: 'BORRAR ESTE ANALISIS?' },
};

@Injectable({ providedIn: 'root' })
export class I18nService {
  private readonly storageKey = 'yari-lang';
  readonly lang = signal<Lang>('en');

  constructor(@Inject(DOCUMENT) private document: Document) {}

  init(): void {
    const stored = localStorage.getItem(this.storageKey);
    const lang: Lang = stored === 'es' ? 'es' : 'en';
    this.lang.set(lang);
    this.document.documentElement.lang = lang;
  }

  toggle(): void {
    const next: Lang = this.lang() === 'en' ? 'es' : 'en';
    this.lang.set(next);
    localStorage.setItem(this.storageKey, next);
    this.document.documentElement.lang = next;
  }

  t(key: string): string {
    const entry = DICT[key];
    if (!entry) {
      return key;
    }
    return entry[this.lang()];
  }
}

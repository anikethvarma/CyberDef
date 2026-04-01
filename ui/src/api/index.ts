import axios, { AxiosHeaders } from 'axios';

export const API_BASE_URL = 'http://10.170.25.3:8000/api/v1';
export const AUTH_STORAGE_KEY = 'cyberdef_auth_token';

let authToken: string | null =
    typeof window !== 'undefined' ? window.localStorage.getItem(AUTH_STORAGE_KEY) : null;

const api = axios.create({
    baseURL: API_BASE_URL,
    headers: {
        'Content-Type': 'application/json',
    },
});

api.interceptors.request.use((config) => {
    if (authToken) {
        const headers = AxiosHeaders.from(config.headers);
        headers.set('Authorization', `Bearer ${authToken}`);
        config.headers = headers;
    }
    return config;
});

export function setAuthToken(token: string | null) {
    authToken = token;
    if (typeof window === 'undefined') return;
    if (token) {
        window.localStorage.setItem(AUTH_STORAGE_KEY, token);
    } else {
        window.localStorage.removeItem(AUTH_STORAGE_KEY);
    }
}

export function getStoredAuthToken(): string | null {
    if (typeof window === 'undefined') return null;
    return window.localStorage.getItem(AUTH_STORAGE_KEY);
}

export interface LoginResponse {
    access_token: string;
    token_type: string;
    expires_in: number;
    username: string;
    emp_id?: string | null;
    name: string;
}

export interface CurrentUserResponse {
    username: string;
    emp_id?: string | null;
    name: string;
}

export const loginRequest = async (username: string, password: string): Promise<LoginResponse> => {
    const response = await api.post('/auth/login', { username, password });
    return response.data;
};

export const getCurrentUser = async (): Promise<CurrentUserResponse> => {
    const response = await api.get('/auth/me');
    return response.data;
};

export const logoutRequest = async (): Promise<void> => {
    await api.post('/auth/logout');
};

function buildAuthQueryParam() {
    return authToken ? `&access_token=${encodeURIComponent(authToken)}` : '';
}

// File endpoints
export const uploadFile = async (file: File) => {
    const formData = new FormData();
    formData.append('file', file);

    const response = await api.post('/files/upload', formData, {
        headers: {
            'Content-Type': 'multipart/form-data',
        },
    });
    return response.data;
};

export const getFiles = async () => {
    const response = await api.get('/files/');
    return response.data;
};

export const getFile = async (fileId: string) => {
    const response = await api.get(`/files/${fileId}`);
    return response.data;
};

// Analysis endpoints
export const analyzeFile = async (fileId: string) => {
    const response = await api.post(`/analyze?file_id=${encodeURIComponent(fileId)}`);
    return response.data;
};

export const getFileReportUrl = (fileId: string, download = true) => {
    const flag = download ? 'true' : 'false';
    return `${API_BASE_URL}/files/${fileId}/report?download=${flag}${buildAuthQueryParam()}`;
};

export const getFileIncidentsJsonUrl = (fileId: string, download = true) => {
    const flag = download ? 'true' : 'false';
    return `${API_BASE_URL}/files/${fileId}/incidents-json?download=${flag}${buildAuthQueryParam()}`;
};

export interface GeneratedReport {
    report_name: string;
    report_path: string;
    file_id: string | null;
    created_at: string;
    size_bytes: number;
}

export interface GeneratedReportContent extends GeneratedReport {
    content: string;
}

export const listGeneratedReports = async (fileId?: string): Promise<GeneratedReport[]> => {
    const params = new URLSearchParams();
    if (fileId) params.append('file_id', fileId);
    const query = params.toString();
    const route = `/files/reports${query ? `?${query}` : ''}`;
    try {
        const response = await api.get(route);
        return response.data;
    } catch (error: any) {
        if (error?.response?.status === 404) {
            const fallbackRoute = `/files/reports/${query ? `?${query}` : ''}`;
            const response = await api.get(fallbackRoute);
            return response.data;
        }
        throw error;
    }
};

export const getFileReportContent = async (fileId: string): Promise<GeneratedReportContent> => {
    const response = await api.get(`/files/${fileId}/report-content`);
    return response.data;
};

export const getFileIncidentsJsonContent = async (fileId: string): Promise<any> => {
    const response = await api.get(`/files/${fileId}/incidents-json?download=false`);
    return response.data;
};

// Incident endpoints
export const getIncidents = async (status?: string, priority?: string, limit = 1000) => {
    const params = new URLSearchParams();
    if (status) params.append('status', status);
    if (priority) params.append('priority', priority);
    if (limit > 0) params.append('limit', String(limit));

    const query = params.toString();
    const response = await api.get(`/incidents/${query ? `?${query}` : ''}`);
    return response.data;
};

export const getIncident = async (incidentId: string) => {
    const response = await api.get(`/incidents/${incidentId}`);
    return response.data;
};

export const updateIncident = async (incidentId: string, update: any) => {
    const response = await api.patch(`/incidents/${incidentId}`, update);
    return response.data;
};

export const getIncidentReport = async (incidentId: string) => {
    const response = await api.get(`/incidents/${incidentId}/report`);
    return response.data;
};

export const getIncidentStats = async () => {
    const response = await api.get('/incidents/stats');
    return response.data;
};

export const getValidationStats = async () => {
    const response = await api.get('/validation');
    return response.data;
};

// Health check
export const healthCheck = async () => {
    const response = await axios.get('http://10.170.25.3:8000/health');
    return response.data;
};

export default api;

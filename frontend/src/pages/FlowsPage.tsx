import { useState, useEffect, useCallback, type FC, type ChangeEvent } from 'react';
import { Link } from 'react-router-dom';
import { Search, Filter, RotateCcw, Eye, Network } from 'lucide-react';
import type { DataService } from '../services/DataService';
import type { PassiveFlow, FlowQueryParams, PaginatedResponse } from '../types';
import { PageHeader } from '../components/layout/PageHeader';
import { StatusPill } from '../components/common/StatusPill';
import { DataStateWrapper, type DataState } from '../components/common/DataStateWrapper';
import { PaginationControls } from '../components/common/PaginationControls';

export interface FlowsPageProps {
  dataService: DataService;
}

const PROTOCOL_OPTIONS = ['ALL', 'TCP', 'UDP', 'TLS', 'QUIC', 'ICMP'];
const DIRECTION_OPTIONS = ['ALL', 'inbound', 'outbound', 'internal', 'unknown'];

export const FlowsPage: FC<FlowsPageProps> = ({ dataService }) => {
  const [dataState, setDataState] = useState<DataState>('loading');
  const [flowsResponse, setFlowsResponse] = useState<PaginatedResponse<PassiveFlow> | null>(null);

  // Filter & Pagination local state
  const [page, setPage] = useState<number>(1);
  const [limit] = useState<number>(10);
  const [protocolFilter, setProtocolFilter] = useState<string>('ALL');
  const [directionFilter, setDirectionFilter] = useState<string>('ALL');
  const [searchIpInput, setSearchIpInput] = useState<string>('');

  const fetchFlows = useCallback(async () => {
    setDataState('loading');
    try {
      const queryParams: FlowQueryParams = {
        page,
        limit,
      };

      if (protocolFilter !== 'ALL') {
        queryParams.protocol = protocolFilter;
      }

      if (directionFilter !== 'ALL') {
        queryParams.direction = directionFilter;
      }

      if (searchIpInput.trim()) {
        queryParams.search_ip = searchIpInput.trim();
      }

      const response = await dataService.getFlows(queryParams);
      setFlowsResponse(response);

      if (response.data.length === 0) {
        setDataState('empty');
      } else {
        setDataState('ready');
      }
    } catch {
      setDataState('error');
    }
  }, [dataService, page, limit, protocolFilter, directionFilter, searchIpInput]);

  useEffect(() => {
    fetchFlows();
  }, [fetchFlows]);

  const handleFilterChange = (setter: (val: string) => void, val: string) => {
    setter(val);
    setPage(1); // Reset to page 1 on filter change
  };

  const handleResetFilters = () => {
    setProtocolFilter('ALL');
    setDirectionFilter('ALL');
    setSearchIpInput('');
    setPage(1);
  };

  return (
    <div className="space-y-6">
      <PageHeader
        title="Passive Flow Explorer"
        description="Normalized passive network flow observations and protocol metadata explorer."
      />

      {/* Filter Control Bar */}
      <div className="rounded-lg border border-[var(--panel-border)] bg-[var(--panel-bg)] p-4 space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-[var(--panel-border-subtle)] pb-3">
          <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-slate-300 font-mono">
            <Filter className="h-4 w-4 text-cyan-400" />
            <span>Flow Filters</span>
          </div>

          <button
            type="button"
            onClick={handleResetFilters}
            className="inline-flex items-center gap-1.5 rounded border border-slate-700 bg-slate-900 px-2.5 py-1 text-xs font-mono text-slate-300 hover:bg-slate-800 hover:text-slate-100 focus-ring"
          >
            <RotateCcw className="h-3 w-3" />
            <span>Reset Filters</span>
          </button>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4 text-xs font-sans">
          {/* IP Search Filter */}
          <div className="space-y-1.5">
            <label htmlFor="flow-ip-search" className="block text-[11px] font-mono text-slate-400">
              Search IP Address
            </label>
            <div className="relative">
              <Search className="absolute left-2.5 top-2.5 h-3.5 w-3.5 text-slate-500" />
              <input
                id="flow-ip-search"
                type="text"
                value={searchIpInput}
                onChange={(e: ChangeEvent<HTMLInputElement>) =>
                  handleFilterChange(setSearchIpInput, e.target.value)
                }
                placeholder="Filter by source or dest IP..."
                className="w-full rounded border border-slate-700 bg-slate-950/80 py-1.5 pl-8 pr-3 font-mono text-xs text-slate-200 placeholder-slate-500 focus-ring"
              />
            </div>
          </div>

          {/* Protocol Filter */}
          <div className="space-y-1.5">
            <label htmlFor="flow-protocol-filter" className="block text-[11px] font-mono text-slate-400">
              Protocol
            </label>
            <select
              id="flow-protocol-filter"
              value={protocolFilter}
              onChange={(e: ChangeEvent<HTMLSelectElement>) =>
                handleFilterChange(setProtocolFilter, e.target.value)
              }
              className="w-full rounded border border-slate-700 bg-slate-950/80 py-1.5 px-2.5 font-mono text-xs text-slate-200 focus-ring"
            >
              {PROTOCOL_OPTIONS.map((proto) => (
                <option key={proto} value={proto}>
                  {proto === 'ALL' ? 'All Protocols' : proto}
                </option>
              ))}
            </select>
          </div>

          {/* Direction Filter */}
          <div className="space-y-1.5">
            <label htmlFor="flow-direction-filter" className="block text-[11px] font-mono text-slate-400">
              Direction
            </label>
            <select
              id="flow-direction-filter"
              value={directionFilter}
              onChange={(e: ChangeEvent<HTMLSelectElement>) =>
                handleFilterChange(setDirectionFilter, e.target.value)
              }
              className="w-full rounded border border-slate-700 bg-slate-950/80 py-1.5 px-2.5 font-mono text-xs text-slate-200 focus-ring"
            >
              {DIRECTION_OPTIONS.map((dir) => (
                <option key={dir} value={dir}>
                  {dir === 'ALL' ? 'All Directions' : dir}
                </option>
              ))}
            </select>
          </div>
        </div>
      </div>

      {/* Main Flow Table View */}
      <DataStateWrapper state={dataState} onRetry={fetchFlows}>
        {flowsResponse && (
          <div className="space-y-4">
            <div className="rounded-lg border border-[var(--panel-border)] bg-[var(--panel-bg)] p-5 space-y-4">
              <div className="flex items-center justify-between border-b border-[var(--panel-border-subtle)] pb-3">
                <h3 className="text-sm font-semibold text-slate-200 uppercase tracking-wider font-mono flex items-center gap-2">
                  <Network className="h-4 w-4 text-cyan-400" />
                  Observed Passive Flows ({flowsResponse.total})
                </h3>
              </div>

              {flowsResponse.data.length === 0 ? (
                <div className="py-8 text-center text-xs text-slate-400 font-sans">
                  No passive network flows found matching criteria.
                </div>
              ) : (
                <div className="overflow-x-auto focus-ring" role="region" aria-label="Passive Network Flow Dataset" tabIndex={0}>
                  <table className="w-full text-left text-xs font-sans">
                    <thead className="bg-slate-950/60 text-slate-400 uppercase tracking-wider font-mono text-[11px] border-b border-slate-800">
                      <tr>
                        <th className="py-2.5 px-3">Timestamp</th>
                        <th className="py-2.5 px-3">Flow ID</th>
                        <th className="py-2.5 px-3">Source IP</th>
                        <th className="py-2.5 px-3">Src Port</th>
                        <th className="py-2.5 px-3">Destination IP</th>
                        <th className="py-2.5 px-3">Dst Port</th>
                        <th className="py-2.5 px-3">Protocol</th>
                        <th className="py-2.5 px-3">Direction</th>
                        <th className="py-2.5 px-3">Duration</th>
                        <th className="py-2.5 px-3">Packets</th>
                        <th className="py-2.5 px-3">Bytes</th>
                        <th className="py-2.5 px-3 text-right">Inspect</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/60">
                      {flowsResponse.data.map((flow) => (
                        <tr
                          key={flow.flow_id}
                          className="hover:bg-slate-800/30 transition-colors"
                        >
                          <td className="py-2.5 px-3 font-mono text-slate-300 whitespace-nowrap">
                            {flow.timestamp}
                          </td>
                          <td className="py-2.5 px-3 font-mono whitespace-nowrap font-medium text-cyan-400">
                            <Link
                              to={`/flows/${flow.flow_id}`}
                              className="hover:underline"
                              title={`Inspect flow ${flow.flow_id}`}
                            >
                              {flow.flow_id}
                            </Link>
                          </td>
                          <td className="py-2.5 px-3 font-mono text-slate-300 whitespace-nowrap">
                            {flow.src_ip}
                          </td>
                          <td className="py-2.5 px-3 font-mono text-slate-400 whitespace-nowrap">
                            {flow.src_port !== null && flow.src_port !== undefined ? flow.src_port : 'N/A'}
                          </td>
                          <td className="py-2.5 px-3 font-mono text-slate-300 whitespace-nowrap">
                            {flow.dst_ip}
                          </td>
                          <td className="py-2.5 px-3 font-mono text-slate-400 whitespace-nowrap">
                            {flow.dst_port !== null && flow.dst_port !== undefined ? flow.dst_port : 'N/A'}
                          </td>
                          <td className="py-2.5 px-3 font-mono text-slate-300 whitespace-nowrap font-bold">
                            {flow.protocol}
                          </td>
                          <td className="py-2.5 px-3 whitespace-nowrap">
                            {flow.direction ? (
                              <StatusPill status={flow.direction} size="sm" />
                            ) : (
                              <span className="text-[11px] font-mono text-slate-500">N/A</span>
                            )}
                          </td>
                          <td className="py-2.5 px-3 font-mono text-slate-300 whitespace-nowrap">
                            {flow.duration !== null && flow.duration !== undefined ? `${flow.duration}s` : 'N/A'}
                          </td>
                          <td className="py-2.5 px-3 font-mono text-slate-300 whitespace-nowrap">
                            {flow.packet_count !== null && flow.packet_count !== undefined
                              ? flow.packet_count.toLocaleString()
                              : 'N/A'}
                          </td>
                          <td className="py-2.5 px-3 font-mono text-slate-300 whitespace-nowrap">
                            {flow.byte_count !== null && flow.byte_count !== undefined
                              ? flow.byte_count.toLocaleString()
                              : 'N/A'}
                          </td>
                          <td className="py-2.5 px-3 text-right whitespace-nowrap">
                            <Link
                              to={`/flows/${flow.flow_id}`}
                              className="inline-flex items-center gap-1 rounded border border-slate-700 bg-slate-800 px-2 py-1 text-[11px] text-slate-200 hover:bg-slate-700 focus-ring font-mono"
                              title="Inspect flow details"
                            >
                              <Eye className="h-3 w-3" />
                              <span>Inspect</span>
                            </Link>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>

            {/* Pagination Controls */}
            <PaginationControls
              page={flowsResponse.page}
              limit={flowsResponse.limit}
              total={flowsResponse.total}
              hasMore={flowsResponse.has_more}
              onPageChange={(newPage) => setPage(newPage)}
            />
          </div>
        )}
      </DataStateWrapper>
    </div>
  );
};

import React, { useState, useEffect, useCallback } from 'react';
import { invoke } from '@tauri-apps/api/tauri';
import { useWallet } from '../App';

// ── Types ──────────────────────────────────────────────────────────────────────

interface TestQuestion { id: string; question: string; options: string[]; }

interface DaoProposal {
  id: string; title: string; description: string; proposal_type: string;
  options: string[]; creator: string; created_at: number; voting_ends_at: number;
  status: string; has_knowledge_test: boolean; question_count: number;
  stake_vote_count: number; knowledge_vote_count: number;
  questions: TestQuestion[] | null;
  my_stake_vote: number | null; my_knowledge_vote: number | null; my_test_score: number | null;
}

interface OptionResult { option: string; stake_power: number; knowledge_power: number; combined_power: number; }

interface ProposalResults {
  proposal_id: string; title: string; options: OptionResult[];
  winning_option_index: number | null; total_stake_voters: number;
  total_knowledge_voters: number; total_staked_in_votes: number;
  quorum_reached: boolean; status: string;
}

interface NewQuestion { question: string; options: string[]; correct_index: number; }

interface BanStatus {
  target: string; vote_count: number; threshold: number; banned: boolean; my_vote: boolean;
}

// ── Helpers ────────────────────────────────────────────────────────────────────

const TYPE_LABELS: Record<string, { label: string; color: string }> = {
  protocol:  { label: 'Protocol',  color: 'bg-purple-500/20 text-purple-300 border-purple-500/30' },
  resource:  { label: 'Resource',  color: 'bg-blue-500/20 text-blue-300 border-blue-500/30' },
  feature:   { label: 'Feature',   color: 'bg-green-500/20 text-green-300 border-green-500/30' },
  parameter: { label: 'Parameter', color: 'bg-yellow-500/20 text-yellow-300 border-yellow-500/30' },
  tender:    { label: 'Tender',    color: 'bg-orange-500/20 text-orange-300 border-orange-500/30' },
};

const STATUS_LABELS: Record<string, { label: string; color: string }> = {
  active:  { label: 'Active',  color: 'bg-green-500/20 text-green-300 border-green-500/30' },
  passed:  { label: 'Passed',  color: 'bg-blue-500/20 text-blue-300 border-blue-500/30' },
  failed:  { label: 'Failed',  color: 'bg-red-500/20 text-red-300 border-red-500/30' },
  expired: { label: 'Expired', color: 'bg-gray-500/20 text-gray-400 border-gray-500/30' },
};

function truncAddr(a: string) { return a.length > 14 ? a.slice(0, 8) + '…' + a.slice(-4) : a; }

function formatDate(ts: number) {
  return new Date(ts * 1000).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
}

function timeLeft(ts: number): string {
  const secs = ts - Math.floor(Date.now() / 1000);
  if (secs <= 0) return 'Ended';
  const d = Math.floor(secs / 86400);
  const h = Math.floor((secs % 86400) / 3600);
  if (d > 0) return `${d}d ${h}h left`;
  const m = Math.floor((secs % 3600) / 60);
  return h > 0 ? `${h}h ${m}m left` : `${m}m left`;
}

function PowerBar({ label, power, color }: { label: string; power: number; color: string }) {
  return (
    <div className="flex items-center gap-2 text-xs">
      <span className="w-20 text-gray-400 shrink-0">{label}</span>
      <div className="flex-1 h-1.5 bg-gray-700 rounded-full overflow-hidden">
        <div className={`h-full rounded-full transition-all ${color}`} style={{ width: `${(power * 100).toFixed(1)}%` }} />
      </div>
      <span className="w-10 text-right text-gray-300">{(power * 100).toFixed(1)}%</span>
    </div>
  );
}

// ── Create Proposal Modal ──────────────────────────────────────────────────────

function CreateProposalModal({ onClose, onCreated }: { onClose: () => void; onCreated: () => void }) {
  const [title, setTitle]       = useState('');
  const [desc, setDesc]         = useState('');
  const [type, setType]         = useState('protocol');
  const [options, setOptions]   = useState(['Yes', 'No']);
  const [days, setDays]         = useState(7);
  const [withTest, setWithTest] = useState(false);
  const [questions, setQuestions] = useState<NewQuestion[]>([
    { question: '', options: ['', '', '', ''], correct_index: 0 }
  ]);
  const [busy, setBusy]   = useState(false);
  const [error, setError] = useState('');

  function addOption() { if (options.length < 6) setOptions([...options, '']); }
  function removeOption(i: number) { if (options.length > 2) setOptions(options.filter((_, j) => j !== i)); }
  function setOption(i: number, v: string) { setOptions(options.map((o, j) => j === i ? v : o)); }

  function addQuestion() {
    setQuestions([...questions, { question: '', options: ['', '', '', ''], correct_index: 0 }]);
  }
  function removeQuestion(i: number) { if (questions.length > 1) setQuestions(questions.filter((_, j) => j !== i)); }
  function setQField(qi: number, field: keyof NewQuestion, val: any) {
    setQuestions(questions.map((q, j) => j === qi ? { ...q, [field]: val } : q));
  }
  function setQOption(qi: number, oi: number, val: string) {
    setQuestions(questions.map((q, j) => j === qi
      ? { ...q, options: q.options.map((o, k) => k === oi ? val : o) }
      : q));
  }

  async function submit() {
    setError(''); setBusy(true);
    try {
      const qs = withTest ? questions.map(q => ({
        question: q.question, options: q.options, correct_index: q.correct_index,
      })) : null;
      await invoke('create_dao_proposal', {
        title, description: desc, proposalType: type,
        options: options.filter(o => o.trim()),
        durationDays: days,
        questions: qs,
      });
      onCreated();
      onClose();
    } catch (e: any) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm">
      <div className="w-full max-w-2xl bg-gray-900 border border-gray-700 rounded-2xl shadow-2xl overflow-hidden flex flex-col max-h-[90vh]">
        <div className="flex items-center justify-between px-6 py-4 border-b border-gray-700">
          <h2 className="text-lg font-semibold text-white">Create DAO Proposal</h2>
          <button onClick={onClose} className="text-gray-400 hover:text-white text-xl leading-none">×</button>
        </div>

        <div className="overflow-y-auto flex-1 px-6 py-5 space-y-5">
          {error && <div className="p-3 bg-red-500/10 border border-red-500/30 rounded-xl text-red-400 text-sm">{error}</div>}

          <div>
            <label className="block text-xs text-gray-400 mb-1">Title</label>
            <input value={title} onChange={e => setTitle(e.target.value)} maxLength={120}
              placeholder="Proposal title…"
              className="w-full bg-gray-800 border border-gray-700 rounded-xl px-3 py-2 text-sm text-white focus:outline-none focus:border-purple-500" />
          </div>

          <div>
            <label className="block text-xs text-gray-400 mb-1">Description</label>
            <textarea value={desc} onChange={e => setDesc(e.target.value)} rows={4}
              placeholder="Explain your proposal in detail…"
              className="w-full bg-gray-800 border border-gray-700 rounded-xl px-3 py-2 text-sm text-white focus:outline-none focus:border-purple-500 resize-none" />
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-xs text-gray-400 mb-1">Type</label>
              <select value={type} onChange={e => setType(e.target.value)}
                className="w-full bg-gray-800 border border-gray-700 rounded-xl px-3 py-2 text-sm text-white focus:outline-none focus:border-purple-500">
                {Object.entries(TYPE_LABELS).map(([k, v]) => <option key={k} value={k}>{v.label}</option>)}
              </select>
            </div>
            <div>
              <label className="block text-xs text-gray-400 mb-1">Voting Duration (days)</label>
              <input type="number" value={days} min={1} max={30} onChange={e => setDays(Number(e.target.value))}
                className="w-full bg-gray-800 border border-gray-700 rounded-xl px-3 py-2 text-sm text-white focus:outline-none focus:border-purple-500" />
            </div>
          </div>

          <div>
            <div className="flex items-center justify-between mb-2">
              <label className="text-xs text-gray-400">Voting Options</label>
              <button onClick={addOption} className="text-xs text-purple-400 hover:text-purple-300">+ Add Option</button>
            </div>
            <div className="space-y-2">
              {options.map((opt, i) => (
                <div key={i} className="flex gap-2">
                  <input value={opt} onChange={e => setOption(i, e.target.value)} maxLength={80}
                    placeholder={`Option ${i + 1}`}
                    className="flex-1 bg-gray-800 border border-gray-700 rounded-xl px-3 py-2 text-sm text-white focus:outline-none focus:border-purple-500" />
                  {options.length > 2 && (
                    <button onClick={() => removeOption(i)} className="px-2 text-gray-500 hover:text-red-400">×</button>
                  )}
                </div>
              ))}
            </div>
          </div>

          <div>
            <label className="flex items-center gap-2 cursor-pointer">
              <div onClick={() => setWithTest(!withTest)}
                className={`w-10 h-5 rounded-full transition-colors relative ${withTest ? 'bg-purple-600' : 'bg-gray-700'}`}>
                <div className={`absolute top-0.5 w-4 h-4 bg-white rounded-full shadow transition-transform ${withTest ? 'translate-x-5' : 'translate-x-0.5'}`} />
              </div>
              <span className="text-sm text-gray-300">Add Knowledge Test</span>
              <span className="text-xs text-gray-500">(voters must pass to cast knowledge vote)</span>
            </label>
          </div>

          {withTest && (
            <div className="space-y-4 border border-gray-700 rounded-xl p-4 bg-gray-800/40">
              <div className="flex items-center justify-between">
                <span className="text-sm font-medium text-white">Knowledge Test Questions</span>
                <button onClick={addQuestion} className="text-xs text-purple-400 hover:text-purple-300">+ Add Question</button>
              </div>
              {questions.map((q, qi) => (
                <div key={qi} className="border border-gray-700 rounded-xl p-3 space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="text-xs text-gray-400 font-medium">Question {qi + 1}</span>
                    {questions.length > 1 && (
                      <button onClick={() => removeQuestion(qi)} className="text-xs text-red-400 hover:text-red-300">Remove</button>
                    )}
                  </div>
                  <input value={q.question} onChange={e => setQField(qi, 'question', e.target.value)}
                    placeholder="Enter question…"
                    className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-purple-500" />
                  <div className="space-y-2">
                    {q.options.map((opt, oi) => (
                      <div key={oi} className="flex items-center gap-2">
                        <input type="radio" name={`q${qi}-correct`} checked={q.correct_index === oi}
                          onChange={() => setQField(qi, 'correct_index', oi)}
                          className="accent-purple-500" title="Mark as correct answer" />
                        <input value={opt} onChange={e => setQOption(qi, oi, e.target.value)}
                          placeholder={`Option ${oi + 1}${q.correct_index === oi ? ' (correct)' : ''}`}
                          className="flex-1 bg-gray-800 border border-gray-600 rounded-lg px-3 py-1.5 text-sm text-white focus:outline-none focus:border-purple-500" />
                      </div>
                    ))}
                  </div>
                  <p className="text-xs text-gray-500">Select the radio button next to the correct answer.</p>
                </div>
              ))}
            </div>
          )}
        </div>

        <div className="px-6 py-4 border-t border-gray-700 flex gap-3 justify-end">
          <button onClick={onClose} className="px-4 py-2 text-sm text-gray-400 hover:text-white transition-colors">Cancel</button>
          <button onClick={submit} disabled={busy || !title.trim()}
            className="px-5 py-2 bg-purple-600 hover:bg-purple-500 disabled:opacity-50 rounded-xl text-sm font-medium text-white transition-colors">
            {busy ? 'Submitting…' : 'Submit Proposal'}
          </button>
        </div>
      </div>
    </div>
  );
}

// ── Proposal Detail Modal ──────────────────────────────────────────────────────

function ProposalDetailModal({ proposal, onClose, onVoted, myAddress }: {
  proposal: DaoProposal; onClose: () => void; onVoted: () => void; myAddress: string;
}) {
  const [results, setResults]         = useState<ProposalResults | null>(null);
  const [stakeOption, setStakeOption] = useState<number | null>(proposal.my_stake_vote ?? null);
  const [knowOption, setKnowOption]   = useState<number | null>(proposal.my_knowledge_vote ?? null);
  const [answers, setAnswers]         = useState<(number | null)[]>(
    proposal.questions ? proposal.questions.map(() => null) : []
  );
  const [testScore, setTestScore]     = useState<number | null>(proposal.my_test_score ?? null);
  const [testSubmitted, setTestSubmitted] = useState(proposal.my_knowledge_vote !== null);
  const [banStatus, setBanStatus]     = useState<BanStatus | null>(null);
  const [banBusy, setBanBusy]         = useState(false);
  const [banConfirm, setBanConfirm]   = useState(false);
  const [busy, setBusy]   = useState('');
  const [error, setError] = useState('');

  const isActive = proposal.status === 'active' && Math.floor(Date.now() / 1000) <= proposal.voting_ends_at;
  const isOwnProposal = proposal.creator === myAddress;

  useEffect(() => {
    invoke<ProposalResults>('get_proposal_results', { proposalId: proposal.id })
      .then(setResults).catch(() => {});
    invoke<BanStatus>('get_ban_status', { targetAddress: proposal.creator })
      .then(setBanStatus).catch(() => {});
  }, [proposal.id, proposal.creator]);

  async function castBanVote() {
    setBanBusy(true);
    try {
      const updated = await invoke<BanStatus>('vote_ban_proposer', { targetAddress: proposal.creator });
      setBanStatus(updated);
      setBanConfirm(false);
    } catch (e: any) { setError(String(e)); }
    finally { setBanBusy(false); }
  }

  async function submitStakeVote() {
    if (stakeOption === null) return;
    setBusy('stake'); setError('');
    try {
      await invoke('cast_stake_vote', { proposalId: proposal.id, optionIndex: stakeOption });
      const r = await invoke<ProposalResults>('get_proposal_results', { proposalId: proposal.id });
      setResults(r);
      onVoted();
    } catch (e: any) { setError(String(e)); }
    finally { setBusy(''); }
  }

  async function submitKnowledgeVote() {
    if (knowOption === null || answers.some(a => a === null)) return;
    setBusy('know'); setError('');
    try {
      const score = await invoke<number>('cast_knowledge_vote', {
        proposalId: proposal.id, optionIndex: knowOption,
        answers: answers.map(a => a ?? 0),
      });
      setTestScore(score);
      setTestSubmitted(true);
      const r = await invoke<ProposalResults>('get_proposal_results', { proposalId: proposal.id });
      setResults(r);
      onVoted();
    } catch (e: any) { setError(String(e)); }
    finally { setBusy(''); }
  }

  async function previewScore() {
    if (answers.some(a => a === null)) return;
    setBusy('preview'); setError('');
    try {
      const score = await invoke<number>('grade_knowledge_test', {
        proposalId: proposal.id, answers: answers.map(a => a ?? 0),
      });
      setTestScore(score);
    } catch (e: any) { setError(String(e)); }
    finally { setBusy(''); }
  }

  const typeInfo   = TYPE_LABELS[proposal.proposal_type]   || { label: proposal.proposal_type, color: 'bg-gray-600/20 text-gray-300 border-gray-600/30' };
  const statusInfo = STATUS_LABELS[proposal.status]        || { label: proposal.status, color: 'bg-gray-600/20 text-gray-300 border-gray-600/30' };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm">
      <div className="w-full max-w-2xl bg-gray-900 border border-gray-700 rounded-2xl shadow-2xl overflow-hidden flex flex-col max-h-[92vh]">
        <div className="flex items-start justify-between px-6 py-4 border-b border-gray-700">
          <div className="flex-1 pr-4">
            <div className="flex items-center gap-2 mb-1">
              <span className={`text-xs px-2 py-0.5 rounded-md border ${typeInfo.color}`}>{typeInfo.label}</span>
              <span className={`text-xs px-2 py-0.5 rounded-md border ${statusInfo.color}`}>{statusInfo.label}</span>
            </div>
            <h2 className="text-lg font-semibold text-white leading-tight">{proposal.title}</h2>
            <p className="text-xs text-gray-500 mt-0.5">
              by {truncAddr(proposal.creator)} · {formatDate(proposal.created_at)} ·{' '}
              {isActive ? <span className="text-green-400">{timeLeft(proposal.voting_ends_at)}</span> : 'Voting ended'}
            </p>
            {/* Ban status / report button */}
            {banStatus && (
              <div className="mt-2 flex items-center gap-2 flex-wrap">
                {banStatus.banned ? (
                  <span className="text-[10px] px-2 py-0.5 rounded-md border bg-red-500/20 text-red-400 border-red-500/30 font-medium">
                    ⛔ Proposer banned by community ({banStatus.vote_count}/{banStatus.threshold} votes)
                  </span>
                ) : (
                  <>
                    <span className="text-[10px] text-gray-600">
                      {banStatus.vote_count}/{banStatus.threshold} removal votes
                    </span>
                    {!isOwnProposal && !banStatus.my_vote && (
                      banConfirm ? (
                        <span className="flex items-center gap-1.5">
                          <span className="text-[10px] text-yellow-400">Report this proposer?</span>
                          <button onClick={castBanVote} disabled={banBusy}
                            className="text-[10px] px-2 py-0.5 rounded bg-red-600 hover:bg-red-500 text-white disabled:opacity-50 transition">
                            {banBusy ? '…' : 'Confirm'}
                          </button>
                          <button onClick={() => setBanConfirm(false)} className="text-[10px] text-gray-500 hover:text-gray-300">Cancel</button>
                        </span>
                      ) : (
                        <button onClick={() => setBanConfirm(true)}
                          className="text-[10px] text-gray-600 hover:text-red-400 transition underline underline-offset-2">
                          Report proposer
                        </button>
                      )
                    )}
                    {banStatus.my_vote && (
                      <span className="text-[10px] text-yellow-500">You reported this proposer</span>
                    )}
                  </>
                )}
              </div>
            )}
          </div>
          <button onClick={onClose} className="text-gray-400 hover:text-white text-xl leading-none shrink-0">×</button>
        </div>

        <div className="overflow-y-auto flex-1 px-6 py-5 space-y-6">
          {error && <div className="p-3 bg-red-500/10 border border-red-500/30 rounded-xl text-red-400 text-sm">{error}</div>}

          <p className="text-sm text-gray-300 leading-relaxed">{proposal.description}</p>

          {/* Stake Vote */}
          <div className="border border-gray-700 rounded-xl p-4 space-y-3">
            <div className="flex items-center gap-2">
              <span className="text-sm font-medium text-white">Stake Vote</span>
              <span className="text-xs text-gray-500">power = your balance / total voting balance</span>
              {proposal.my_stake_vote !== null && (
                <span className="ml-auto text-xs text-green-400">✓ Voted: {proposal.options[proposal.my_stake_vote]}</span>
              )}
            </div>
            <div className="grid grid-cols-2 gap-2">
              {proposal.options.map((opt, i) => (
                <button key={i} onClick={() => isActive && setStakeOption(i)} disabled={!isActive}
                  className={`px-3 py-2 rounded-xl text-sm border transition-all text-left ${
                    stakeOption === i
                      ? 'bg-purple-600/20 border-purple-500 text-purple-300'
                      : 'bg-gray-800 border-gray-700 text-gray-300 hover:border-gray-500 disabled:opacity-50'
                  }`}>
                  {opt}
                </button>
              ))}
            </div>
            {isActive && proposal.my_stake_vote === null && (
              <button onClick={submitStakeVote} disabled={stakeOption === null || busy === 'stake'}
                className="w-full py-2 bg-purple-600 hover:bg-purple-500 disabled:opacity-50 rounded-xl text-sm font-medium text-white transition-colors">
                {busy === 'stake' ? 'Casting vote…' : 'Cast Stake Vote'}
              </button>
            )}
          </div>

          {/* Knowledge Test */}
          {proposal.has_knowledge_test && proposal.questions && (
            <div className="border border-gray-700 rounded-xl p-4 space-y-4">
              <div className="flex items-center gap-2">
                <span className="text-sm font-medium text-white">Knowledge Test</span>
                <span className="text-xs text-gray-500">power = (score / max) × 10</span>
                {testScore !== null && (
                  <span className={`ml-auto text-xs font-medium ${testScore >= 0.6 ? 'text-green-400' : 'text-yellow-400'}`}>
                    Score: {(testScore * 100).toFixed(0)}%
                  </span>
                )}
              </div>
              {proposal.questions.map((q, qi) => (
                <div key={q.id} className="space-y-2">
                  <p className="text-sm text-gray-200">{qi + 1}. {q.question}</p>
                  <div className="grid grid-cols-2 gap-2">
                    {q.options.map((opt, oi) => (
                      <button key={oi}
                        onClick={() => !testSubmitted && setAnswers(answers.map((a, j) => j === qi ? oi : a))}
                        disabled={testSubmitted}
                        className={`px-3 py-2 rounded-xl text-xs border text-left transition-all ${
                          answers[qi] === oi
                            ? 'bg-blue-600/20 border-blue-500 text-blue-300'
                            : 'bg-gray-800 border-gray-700 text-gray-300 hover:border-gray-500 disabled:opacity-50'
                        }`}>
                        {opt}
                      </button>
                    ))}
                  </div>
                </div>
              ))}

              {!testSubmitted && isActive && (
                <div className="space-y-2">
                  <div className="flex items-center gap-2">
                    <label className="text-xs text-gray-400">Vote for:</label>
                    <select value={knowOption ?? ''} onChange={e => setKnowOption(Number(e.target.value))}
                      className="flex-1 bg-gray-800 border border-gray-700 rounded-lg px-2 py-1 text-xs text-white focus:outline-none focus:border-purple-500">
                      <option value="">Select option…</option>
                      {proposal.options.map((opt, i) => <option key={i} value={i}>{opt}</option>)}
                    </select>
                  </div>
                  <div className="flex gap-2">
                    <button onClick={previewScore} disabled={answers.some(a => a === null) || busy === 'preview'}
                      className="flex-1 py-2 bg-gray-700 hover:bg-gray-600 disabled:opacity-50 rounded-xl text-xs text-white transition-colors">
                      {busy === 'preview' ? 'Grading…' : 'Preview Score'}
                    </button>
                    <button onClick={submitKnowledgeVote}
                      disabled={answers.some(a => a === null) || knowOption === null || busy === 'know'}
                      className="flex-1 py-2 bg-blue-600 hover:bg-blue-500 disabled:opacity-50 rounded-xl text-xs font-medium text-white transition-colors">
                      {busy === 'know' ? 'Submitting…' : 'Submit & Vote'}
                    </button>
                  </div>
                </div>
              )}
              {testSubmitted && proposal.my_knowledge_vote !== null && (
                <p className="text-xs text-green-400 text-center">
                  ✓ Knowledge vote cast for: {proposal.options[proposal.my_knowledge_vote]}
                </p>
              )}
            </div>
          )}

          {/* Results */}
          {results && results.options.length > 0 && (
            <div className="border border-gray-700 rounded-xl p-4 space-y-3">
              {/* Results header */}
              <div className="flex items-center justify-between flex-wrap gap-2">
                <span className="text-sm font-medium text-white">Results</span>
                <div className="flex items-center gap-2 flex-wrap">
                  <span className={`text-[10px] px-2 py-0.5 rounded-md border font-medium ${
                    results.quorum_reached
                      ? 'bg-green-500/15 text-green-400 border-green-500/30'
                      : 'bg-yellow-500/15 text-yellow-400 border-yellow-500/30'
                  }`}>
                    {results.quorum_reached ? '✓ Quorum reached' : '⏳ Quorum needed'}
                  </span>
                  <span className="text-[10px] text-gray-500">
                    {results.total_stake_voters} stake · {results.total_knowledge_voters} knowledge voters
                  </span>
                </div>
              </div>

              {/* EGOC participation */}
              {results.total_staked_in_votes > 0 && (
                <div className="text-[10px] text-gray-500 bg-gray-800/60 rounded-lg px-3 py-1.5 flex items-center justify-between">
                  <span>Total EGOC weight in vote</span>
                  <span className="text-purple-300 font-medium">
                    {(results.total_staked_in_votes / 1_000_000).toLocaleString(undefined, { maximumFractionDigits: 0 })} EGOC
                  </span>
                </div>
              )}

              {/* Winner banner — only when voting ended */}
              {!isActive && results.winning_option_index !== null && results.quorum_reached && (
                <div className="flex items-center gap-2 bg-green-500/10 border border-green-500/30 rounded-xl px-4 py-2.5">
                  <span className="text-green-400 text-base">✓</span>
                  <div>
                    <div className="text-xs text-gray-400 leading-none mb-0.5">Winner</div>
                    <div className="text-sm font-semibold text-green-300">
                      {results.options[results.winning_option_index]?.option}
                    </div>
                  </div>
                  <span className={`ml-auto text-xs px-2 py-0.5 rounded-md border ${
                    results.status === 'passed'
                      ? 'bg-blue-500/20 text-blue-300 border-blue-500/30'
                      : 'bg-gray-500/20 text-gray-400 border-gray-500/30'
                  }`}>{results.status}</span>
                </div>
              )}
              {!isActive && !results.quorum_reached && (
                <div className="flex items-center gap-2 bg-red-500/10 border border-red-500/30 rounded-xl px-4 py-2.5">
                  <span className="text-red-400 text-base">✗</span>
                  <span className="text-sm text-red-300">Failed — quorum not reached</span>
                </div>
              )}

              {/* Per-option bars */}
              {results.options.map((opt, i) => {
                const isWinner = results.winning_option_index === i;
                return (
                  <div key={i} className={`space-y-1.5 p-3 rounded-xl ${
                    isWinner ? 'bg-purple-600/10 border border-purple-500/30' : 'bg-gray-800/40'
                  }`}>
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-sm text-white font-medium">{opt.option}</span>
                      <div className="flex items-center gap-2">
                        {isWinner && isActive && (
                          <span className="text-[10px] text-purple-400 font-medium bg-purple-500/10 px-1.5 py-0.5 rounded">Leading</span>
                        )}
                        <span className="text-[11px] text-gray-400 font-mono">
                          {(opt.combined_power * 100).toFixed(1)}%
                        </span>
                      </div>
                    </div>
                    <PowerBar label="Stake"     power={opt.stake_power}     color="bg-purple-500" />
                    <PowerBar label="Knowledge" power={opt.knowledge_power} color="bg-blue-500" />
                    <PowerBar label="Combined"  power={opt.combined_power}  color="bg-gradient-to-r from-purple-500 to-blue-500" />
                  </div>
                );
              })}

              <p className="text-[10px] text-gray-600 text-center">
                Combined = (Stake weight + Knowledge score) ÷ 2
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ── Proposal Card ──────────────────────────────────────────────────────────────

function ProposalCard({ proposal, onClick }: { proposal: DaoProposal; onClick: () => void }) {
  const typeInfo   = TYPE_LABELS[proposal.proposal_type]   || { label: proposal.proposal_type, color: 'bg-gray-600/20 text-gray-300 border-gray-600/30' };
  const statusInfo = STATUS_LABELS[proposal.status]        || { label: proposal.status, color: 'bg-gray-600/20 text-gray-300 border-gray-600/30' };
  const isActive   = proposal.status === 'active' && Math.floor(Date.now() / 1000) <= proposal.voting_ends_at;
  const hasStaked  = proposal.my_stake_vote !== null;
  const hasKnow    = proposal.my_knowledge_vote !== null;

  return (
    <div onClick={onClick}
      className="bg-gray-800/60 border border-gray-700 hover:border-gray-600 rounded-2xl p-5 cursor-pointer transition-all hover:bg-gray-800/80 group">
      <div className="flex items-start justify-between gap-3 mb-3">
        <div className="flex items-center gap-2 flex-wrap">
          <span className={`text-xs px-2 py-0.5 rounded-md border ${typeInfo.color}`}>{typeInfo.label}</span>
          <span className={`text-xs px-2 py-0.5 rounded-md border ${statusInfo.color}`}>{statusInfo.label}</span>
          {proposal.has_knowledge_test && (
            <span className="text-xs px-2 py-0.5 rounded-md border bg-indigo-500/20 text-indigo-300 border-indigo-500/30">
              Knowledge Test
            </span>
          )}
        </div>
        <div className="flex items-center gap-1.5 shrink-0">
          {hasStaked  && <span title="You cast a stake vote"    className="text-green-400 text-xs">🗳</span>}
          {hasKnow    && <span title="You cast a knowledge vote" className="text-blue-400 text-xs">🧠</span>}
        </div>
      </div>

      <h3 className="text-sm font-semibold text-white mb-1 group-hover:text-purple-300 transition-colors leading-snug">
        {proposal.title}
      </h3>
      <p className="text-xs text-gray-400 line-clamp-2 mb-3">{proposal.description}</p>

      <div className="flex items-center justify-between text-xs text-gray-500">
        <span className="flex items-center gap-1.5">
          by {truncAddr(proposal.creator)}
        </span>
        <span className="flex items-center gap-3">
          <span>🗳 {proposal.stake_vote_count}</span>
          {proposal.has_knowledge_test && <span>🧠 {proposal.knowledge_vote_count}</span>}
          {isActive
            ? <span className="text-green-400">{timeLeft(proposal.voting_ends_at)}</span>
            : <span>{formatDate(proposal.voting_ends_at)}</span>
          }
        </span>
      </div>
    </div>
  );
}

// ── Main Page ──────────────────────────────────────────────────────────────────

const TABS = [
  { key: 'active',  label: 'Active' },
  { key: 'all',     label: 'All' },
  { key: 'passed',  label: 'Passed' },
  { key: 'failed',  label: 'Failed' },
  { key: 'expired', label: 'Expired' },
];

interface RateLimit { used: number; max: number; window_hours: number; resets_in_secs: number; }

function fmtCountdown(secs: number): string {
  const h = Math.floor(secs / 3600);
  const m = Math.floor((secs % 3600) / 60);
  return h > 0 ? `${h}h ${m}m` : `${m}m`;
}

export default function GovernancePage() {
  const { wallet } = useWallet();
  const [proposals, setProposals]   = useState<DaoProposal[]>([]);
  const [rateLimit, setRateLimit]   = useState<RateLimit | null>(null);
  const [tab, setTab]               = useState('active');
  const [selected, setSelected]     = useState<DaoProposal | null>(null);
  const [showCreate, setShowCreate] = useState(false);
  const [loading, setLoading]       = useState(true);

  const loadProposals = useCallback(async (statusFilter?: string) => {
    setLoading(true);
    try {
      const list = await invoke<DaoProposal[]>('get_dao_proposals', { statusFilter: statusFilter || tab });
      setProposals(list);
    } catch { setProposals([]); }
    finally { setLoading(false); }
  }, [tab]);

  const refreshRateLimit = useCallback(async () => {
    try { setRateLimit(await invoke<RateLimit>('get_proposal_rate_limit')); } catch {}
  }, []);

  useEffect(() => { loadProposals(tab); }, [tab]);
  useEffect(() => { refreshRateLimit(); }, [refreshRateLimit]);

  async function refreshSelected() {
    if (!selected) return;
    try {
      const p = await invoke<DaoProposal>('get_dao_proposal', { proposalId: selected.id });
      setSelected(p);
      loadProposals(tab);
      refreshRateLimit();
    } catch {}
  }

  const activeCount = proposals.filter(p => p.status === 'active').length;
  const myVoteCount = proposals.filter(p => p.my_stake_vote !== null || p.my_knowledge_vote !== null).length;
  const atLimit     = rateLimit ? rateLimit.used >= rateLimit.max : false;
  const slotsLeft   = rateLimit ? rateLimit.max - rateLimit.used : rateLimit === null ? '…' : rateLimit!.max;

  return (
    <div className="h-full flex flex-col bg-gray-900 overflow-hidden">
      {/* Header */}
      <div className="px-6 pt-6 pb-4 border-b border-gray-800 flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-white">DAO Governance</h1>
          <p className="text-xs text-gray-500 mt-0.5">Decentralized community decision-making</p>
        </div>
        <div className="flex flex-col items-end gap-1">
          <button onClick={() => !atLimit && setShowCreate(true)} disabled={atLimit}
            title={atLimit ? `Rate limit: 5 proposals per 4 hours` : 'Submit a new proposal'}
            className="flex items-center gap-2 px-4 py-2 bg-purple-600 hover:bg-purple-500 disabled:opacity-40 disabled:cursor-not-allowed rounded-xl text-sm font-medium text-white transition-colors">
            <span>+</span> New Proposal
          </button>
          {rateLimit && (
            <span className={`text-[10px] ${atLimit ? 'text-red-400' : 'text-gray-500'}`}>
              {atLimit
                ? `Rate limited — resets in ${fmtCountdown(rateLimit.resets_in_secs)}`
                : `${rateLimit.used}/${rateLimit.max} used · resets every ${rateLimit.window_hours}h`}
            </span>
          )}
        </div>
      </div>

      {/* Stats */}
      <div className="px-6 py-3 border-b border-gray-800 flex items-center gap-6 text-sm">
        <div className="flex items-center gap-2">
          <span className="w-2 h-2 bg-green-400 rounded-full" />
          <span className="text-gray-400">Active:</span>
          <span className="text-white font-medium">{activeCount}</span>
        </div>
        {rateLimit && (
          <div className="flex items-center gap-2">
            <span className="text-gray-400">My proposals (4h):</span>
            <span className={`font-medium ${atLimit ? 'text-red-400' : 'text-white'}`}>
              {rateLimit.used}/{rateLimit.max}
            </span>
          </div>
        )}
        <div className="flex items-center gap-2">
          <span className="text-gray-400">My votes:</span>
          <span className="text-white font-medium">{myVoteCount}</span>
        </div>
        <div className="ml-auto flex items-center gap-2 text-xs text-gray-500">
          <span>Two-type voting:</span>
          <span className="text-purple-400">Stake</span>
          <span>+</span>
          <span className="text-blue-400">Knowledge</span>
          <span>→ averaged</span>
        </div>
      </div>

      {/* Tabs */}
      <div className="px-6 flex items-center gap-1 border-b border-gray-800 py-2">
        {TABS.map(t => (
          <button key={t.key} onClick={() => setTab(t.key)}
            className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${
              tab === t.key
                ? 'bg-purple-600/20 text-purple-300 border border-purple-500/30'
                : 'text-gray-400 hover:text-white'
            }`}>
            {t.label}
          </button>
        ))}
      </div>

      {/* Proposals */}
      <div className="flex-1 overflow-y-auto px-6 py-5">
        {loading ? (
          <div className="flex items-center justify-center h-40 text-gray-500 text-sm">Loading proposals…</div>
        ) : proposals.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-40 text-center space-y-3">
            <span className="text-4xl">🗳️</span>
            <p className="text-gray-400 text-sm">No {tab === 'all' ? '' : tab + ' '}proposals yet.</p>
            <button onClick={() => setShowCreate(true)}
              className="text-xs text-purple-400 hover:text-purple-300 underline underline-offset-2">
              Submit the first proposal
            </button>
          </div>
        ) : (
          <div className="grid grid-cols-1 gap-4">
            {proposals.map(p => (
              <ProposalCard key={p.id} proposal={p} onClick={() => setSelected(p)} />
            ))}
          </div>
        )}
      </div>

      {/* Modals */}
      {showCreate && (
        <CreateProposalModal
          onClose={() => setShowCreate(false)}
          onCreated={() => { loadProposals(tab); refreshRateLimit(); }}
        />
      )}
      {selected && (
        <ProposalDetailModal
          proposal={selected}
          myAddress={wallet?.address ?? ''}
          onClose={() => setSelected(null)}
          onVoted={refreshSelected}
        />
      )}
    </div>
  );
}

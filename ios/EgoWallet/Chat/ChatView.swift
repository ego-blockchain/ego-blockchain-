import EgoKit
import SwiftUI

@MainActor
final class ChatModel: ObservableObject {
    @Published var feed: ChatFeed?
    @Published var problem: String?
    @Published var sending = false

    func load(_ app: AppModel) async {
        let viewer = app.address
        do {
            feed = try await app.perform { try await $0.chatFeed(viewer: viewer) }
            problem = nil
        } catch {
            problem = app.message(for: error)
        }
    }

    func submit(_ app: AppModel, _ make: (EgoKey, Int64) throws -> ChatWire) async -> Bool {
        guard let key = app.key else {
            problem = WalletError.locked.errorDescription
            return false
        }
        sending = true
        defer { sending = false }
        do {
            let wire = try make(key, Int64(Date().timeIntervalSince1970))
            try await app.perform { try await $0.chatSubmit(wire) }
            await load(app)
            return true
        } catch {
            problem = app.message(for: error)
            return false
        }
    }
}

struct ChatView: View {
    @EnvironmentObject private var app: AppModel
    @StateObject private var chat = ChatModel()
    @State private var draft = ""
    @State private var naming = false
    @State private var nameDraft = ""
    @State private var editing: ChatPostView?
    @State private var editDraft = ""
    @State private var voteTarget: ChatPostView?
    @State private var deleteTarget: ChatPostView?

    var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                if let problem = chat.problem {
                    ProblemBanner(text: problem).padding(.horizontal, 12).padding(.top, 8)
                }
                ScrollViewReader { proxy in
                    ScrollView {
                        LazyVStack(alignment: .leading, spacing: 4) {
                            if let feed = chat.feed {
                                Text("Everyone on Ego can read this. \(feed.threshold) removal votes within \(feed.banDays) days remove someone for \(feed.banDays) days.")
                                    .font(.caption)
                                    .foregroundStyle(Brand.muted)
                                    .padding(.vertical, 8)
                                if feed.posts.isEmpty {
                                    Text("No messages yet. Say hello.")
                                        .foregroundStyle(Brand.muted)
                                        .padding(.top, 40)
                                        .frame(maxWidth: .infinity)
                                }
                                ForEach(feed.posts) { post in
                                    ChatRow(post: post, threshold: feed.threshold)
                                        .id(post.id)
                                        .contextMenu { menu(for: post) }
                                }
                            } else {
                                ProgressView().frame(maxWidth: .infinity).padding(.top, 40)
                            }
                        }
                        .padding(.horizontal, 12)
                    }
                    .onChange(of: chat.feed?.posts.last?.id) { _, last in
                        if let last { withAnimation { proxy.scrollTo(last, anchor: .bottom) } }
                    }
                }
                composer
            }
            .screenBackground()
            .navigationTitle("Community chat")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button(chat.feed?.myName.isEmpty == false ? "Name" : "Set name") {
                        nameDraft = chat.feed?.myName ?? ""
                        naming = true
                    }
                }
            }
            .alert("Your name in the chat", isPresented: $naming) {
                TextField("Name", text: $nameDraft)
                Button("Save") { Task { await saveName() } }
                Button("Cancel", role: .cancel) {}
            } message: {
                Text("Up to 24 characters. Your address is always shown next to it.")
            }
            .alert("Edit message", isPresented: Binding(get: { editing != nil }, set: { if !$0 { editing = nil } })) {
                TextField("Message", text: $editDraft)
                Button("Save") { Task { await saveEdit() } }
                Button("Cancel", role: .cancel) { editing = nil }
            } message: {
                Text("You can change a message for one hour after posting it.")
            }
            .confirmationDialog(
                "Vote to remove \(voteTarget.map { $0.name.isEmpty ? shortAddress($0.from) : $0.name } ?? "")?",
                isPresented: Binding(get: { voteTarget != nil }, set: { if !$0 { voteTarget = nil } }),
                titleVisibility: .visible
            ) {
                Button("Vote to remove", role: .destructive) { Task { await vote() } }
            } message: {
                Text("\(chat.feed?.threshold ?? 5) votes within \(chat.feed?.banDays ?? 14) days remove them from the chat for \(chat.feed?.banDays ?? 14) days. A vote can't be taken back.")
            }
            .confirmationDialog(
                "Delete this message?",
                isPresented: Binding(get: { deleteTarget != nil }, set: { if !$0 { deleteTarget = nil } }),
                titleVisibility: .visible
            ) {
                Button("Delete", role: .destructive) { Task { await delete() } }
            } message: {
                Text("It disappears for everyone.")
            }
            .task {
                while !Task.isCancelled {
                    await chat.load(app)
                    try? await Task.sleep(for: .seconds(15))
                }
            }
        }
    }

    @ViewBuilder
    private func menu(for post: ChatPostView) -> some View {
        Button {
            UIPasteboard.general.string = post.body
        } label: {
            Label("Copy text", systemImage: "doc.on.doc")
        }
        if post.mine, let until = post.changeUntil, until > Int64(Date().timeIntervalSince1970) {
            Button {
                editDraft = post.body
                editing = post
            } label: {
                Label("Edit", systemImage: "pencil")
            }
            Button(role: .destructive) {
                deleteTarget = post
            } label: {
                Label("Delete", systemImage: "trash")
            }
        }
        if !post.mine {
            Button(role: .destructive) {
                voteTarget = post
            } label: {
                Label(post.myVote ? "You voted to remove" : "Vote to remove", systemImage: "hand.raised")
            }
            .disabled(post.myVote)
        }
    }

    private var composer: some View {
        VStack(spacing: 6) {
            if let until = chat.feed?.myRemovedUntil {
                Text("Community votes removed you from the chat until \(Date(timeIntervalSince1970: TimeInterval(until)).formatted(date: .abbreviated, time: .omitted)).")
                    .font(.footnote)
                    .foregroundStyle(Brand.danger)
                    .frame(maxWidth: .infinity, alignment: .leading)
            } else {
                HStack(alignment: .bottom, spacing: 8) {
                    TextField("Message everyone…", text: $draft, axis: .vertical)
                        .lineLimit(1...5)
                        .padding(10)
                        .background(Brand.raised)
                        .clipShape(RoundedRectangle(cornerRadius: 12, style: .continuous))
                    Button {
                        Task { await post() }
                    } label: {
                        Image(systemName: "arrow.up.circle.fill").font(.system(size: 30))
                    }
                    .disabled(chat.sending || ChatRules.cleanBody(draft) == nil)
                }
                Text("\(draft.unicodeScalars.count)/\(ChatRules.maxBodyCharacters)")
                    .font(.caption2)
                    .foregroundStyle(Brand.muted)
                    .frame(maxWidth: .infinity, alignment: .trailing)
            }
        }
        .padding(12)
        .background(Brand.card)
    }

    private func post() async {
        guard let text = ChatRules.cleanBody(draft) else { return }
        let name = chat.feed?.myName ?? ""
        if await chat.submit(app, { key, now in .post(try ChatSigner.post(key: key, name: name, body: text, ts: now)) }) {
            draft = ""
        }
    }

    private func saveName() async {
        guard let name = ChatRules.cleanName(nameDraft) else {
            chat.problem = "A name can be at most \(ChatRules.maxNameCharacters) characters."
            return
        }
        _ = await chat.submit(app, { key, now in .name(try ChatSigner.name(key: key, name: name, ts: now)) })
    }

    private func saveEdit() async {
        guard let post = editing, let text = ChatRules.cleanBody(editDraft) else { return }
        editing = nil
        _ = await chat.submit(app, { key, now in .edit(try ChatSigner.edit(key: key, postId: post.id, postTs: post.ts, body: text, ts: now)) })
    }

    private func delete() async {
        guard let post = deleteTarget else { return }
        deleteTarget = nil
        _ = await chat.submit(app, { key, now in .delete(try ChatSigner.delete(key: key, postId: post.id, postTs: post.ts, ts: now)) })
    }

    private func vote() async {
        guard let post = voteTarget else { return }
        voteTarget = nil
        _ = await chat.submit(app, { key, now in .vote(try ChatSigner.vote(key: key, target: post.from, ts: now)) })
    }
}

struct ChatRow: View {
    let post: ChatPostView
    let threshold: Int

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Circle()
                .fill(color(for: post.from))
                .frame(width: 32, height: 32)
                .overlay(
                    Text(String((post.name.isEmpty ? String(post.from.dropFirst(5)) : post.name).prefix(1)).uppercased())
                        .font(.system(size: 13, weight: .bold, design: .rounded))
                        .foregroundStyle(.white)
                )
            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 6) {
                    Text(post.name.isEmpty ? shortAddress(post.from) : post.name)
                        .font(.subheadline.weight(.semibold))
                        .foregroundStyle(Brand.text)
                    if !post.name.isEmpty {
                        Text(shortAddress(post.from))
                            .font(.system(.caption2, design: .monospaced))
                            .foregroundStyle(Brand.muted)
                    }
                    Text(relativeTime(post.ts) + (post.edited ? " · edited" : ""))
                        .font(.caption2)
                        .foregroundStyle(Brand.muted)
                }
                Text(post.body)
                    .font(.body)
                    .foregroundStyle(Brand.text)
                    .textSelection(.enabled)
                if !post.mine && post.removalVotes > 0 {
                    Text("\(post.removalVotes)/\(threshold) to remove")
                        .font(.caption2.weight(.semibold))
                        .foregroundStyle(Brand.danger)
                }
            }
            Spacer(minLength: 0)
        }
        .padding(10)
        .background(post.mine ? Brand.lime.opacity(0.08) : Color.clear)
        .clipShape(RoundedRectangle(cornerRadius: 12, style: .continuous))
    }

    private func color(for address: String) -> Color {
        let hue = Double(address.unicodeScalars.reduce(0) { ($0 &* 31 &+ Int($1.value)) % 360 }) / 360
        return Color(hue: hue, saturation: 0.45, brightness: 0.55)
    }
}

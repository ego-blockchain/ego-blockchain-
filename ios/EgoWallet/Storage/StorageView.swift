import EgoKit
import SwiftUI

struct StorageView: View {
    @EnvironmentObject private var app: AppModel
    @State private var capacity: StorageCapacity?
    @State private var problem: String?
    @State private var pulse = false

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    capacityCard
                    if let problem {
                        ProblemBanner(text: problem)
                    }
                    uploadCard
                    explainer
                }
                .padding(16)
            }
            .refreshable { await load() }
            .screenBackground()
            .navigationTitle("Storage")
            .task {
                while !Task.isCancelled {
                    await load()
                    try? await Task.sleep(for: .seconds(30))
                }
            }
        }
    }

    private var capacityCard: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 8) {
                Circle()
                    .fill(capacity == nil ? Brand.muted : Brand.mint)
                    .frame(width: 8, height: 8)
                    .opacity(pulse ? 0.35 : 1)
                    .animation(.easeInOut(duration: 1.2).repeatForever(autoreverses: true), value: pulse)
                    .onAppear { pulse = true }
                SectionLabel(text: "Free right now")
            }
            Text(capacity.map { ByteCountFormatter.string(fromByteCount: Int64(clamping: $0.freeBytes), countStyle: .decimal) } ?? "…")
                .font(.system(size: 40, weight: .heavy, design: .rounded))
                .foregroundStyle(Brand.text)
                .contentTransition(.numericText())
            Text(capacity.map { "On \($0.providers) Ego Desktop computer\($0.providers == 1 ? "" : "s") sharing storage" } ?? "Checking the network…")
                .font(.subheadline)
                .foregroundStyle(Brand.muted)
            if let capacity {
                Text("Updated \(relativeTime(capacity.updatedAt))")
                    .font(.caption)
                    .foregroundStyle(Brand.muted)
            }
        }
        .card()
    }

    private var uploadCard: some View {
        VStack(alignment: .leading, spacing: 10) {
            SectionLabel(text: "Store files from this iPhone")
            Text("Your files are encrypted on this phone before they leave it, then kept on several Ego Desktop computers. Only you can open them.")
                .font(.subheadline)
                .foregroundStyle(Brand.text)
            Button {
            } label: {
                Label("Choose files", systemImage: "doc.badge.plus")
            }
            .buttonStyle(SecondaryButtonStyle())
            .disabled(true)
            Text("Uploading from the phone is the next step being built. The space above is live.")
                .font(.caption)
                .foregroundStyle(Brand.muted)
        }
        .card()
    }

    private var explainer: some View {
        VStack(alignment: .leading, spacing: 8) {
            SectionLabel(text: "Where the space comes from")
            Text("People running Ego Desktop set aside part of their disk for the network and earn EGOC for keeping other people's files. This number adds up the free space those computers reported in the last 30 minutes.")
                .font(.footnote)
                .foregroundStyle(Brand.muted)
        }
        .card()
    }

    private func load() async {
        do {
            capacity = try await app.perform { try await $0.storageCapacity() }
            problem = nil
        } catch {
            problem = app.message(for: error)
        }
    }
}

// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "EgoKit",
    platforms: [.iOS(.v17), .macOS(.v14)],
    products: [
        .library(name: "EgoKit", targets: ["EgoKit"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-crypto.git", "3.0.0" ..< "5.0.0"),
    ],
    targets: [
        .target(
            name: "EgoKit",
            dependencies: [
                .product(name: "Crypto", package: "swift-crypto", condition: .when(platforms: [.linux, .windows, .android])),
            ]
        ),
        .testTarget(name: "EgoKitTests", dependencies: ["EgoKit"]),
    ]
)

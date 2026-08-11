export type ImageSize = { width: number; height: number; type: "gif" | "ico" | "jpg" | "png" | "webp" };
export declare function imageSize(input: Uint8Array): ImageSize;
export default imageSize;

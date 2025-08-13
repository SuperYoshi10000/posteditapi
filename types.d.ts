export interface User {
    id: number;
    name: string;
    email: string;
    posts?: Post[];
}
export interface Account {
    user: User;
    key: string; // API key
}
export interface Post {
    id: number;
    name: string;
    content: string;
    comments?: Comment[];
}
export interface Comment {
    id: number;
    postId: number;
    content: string;
    parentId?: number; // For replies
    replies?: Comment[];
}

class Post:
    def __init__(self, post_id: str, post_description: str, post_images: list, post_comments: list):
        self.post_id = post_id
        self.post_description = post_description
        self.post_images = post_images
        self.post_comments = post_comments
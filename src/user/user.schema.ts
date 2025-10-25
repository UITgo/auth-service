import {Schema, Prop, SchemaFactory} from '@nestjs/mongoose';
import {Document} from 'mongoose';

@Schema()
export class User extends Document {
    @Prop({required: true, unique: true})
    email: string;
    
    @Prop({required: true, unique: true})
    phone: string;

    @Prop({required: true})
    password: string;

    @Prop({default: false})
    isEmailVerified: boolean;

    @Prop({default: false})
    isDriver: boolean;
}

export const UserSchema = SchemaFactory.createForClass(User);